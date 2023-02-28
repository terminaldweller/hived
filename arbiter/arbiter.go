package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/proxy"
)

var (
	errBadLogic          = errors.New("we should not be here")
	errUnexpectedParam   = errors.New("got unexpected parameter")
	errUnknownDeployment = errors.New("unknown deployment kind")
)

const (
	serverDeploymentType    = "SERVER_DEPLOYMENT_TYPE"
	coingeckoAPIURLv3       = "https://api.coingecko.com/api/v3"
	coincapAPIURLv2         = "https://api.coincap.io/v2"
	getTimeout              = 5
	httpClientTimeout       = 5
	serverTLSReadTimeout    = 15
	serverTLSWriteTimeout   = 15
	defaultGracefulShutdown = 15
)

// https://docs.coincap.io/
type CoinCapAssetGetResponseData struct {
	ID                string `json:"id"`
	Rank              string `json:"rank"`
	Symbol            string `json:"symbol"`
	Name              string `json:"name"`
	Supply            string `json:"supply"`
	MaxSupply         string `json:"maxSupply"`
	MarketCapUsd      string `json:"marketCapUsd"`
	VolumeUsd24Hr     string `json:"volumeUsd24Hr"`
	PriceUsd          string `json:"priceUsd"`
	ChangePercent24Hr string `json:"changePercent24Hr"`
	Vwap24Hr          string `json:"vwap24Hr"`
}

type priceResponseData struct {
	Name         string  `json:"name"`
	Price        float64 `json:"price"`
	Unit         string  `json:"unit"`
	Err          string  `json:"err"`
	IsSuccessful bool    `json:"isSuccessful"`
}

type CoinCapAssetGetResponse struct {
	Data      CoinCapAssetGetResponseData `json:"data"`
	TimeStamp int64                       `json:"timestamp"`
}

type HTTPHandlerFunc func(http.ResponseWriter, *http.Request)

type HTTPHandler struct {
	name     string
	function HTTPHandlerFunc
}

type priceChanStruct struct {
	name  string
	price float64
}

type errorChanStruct struct {
	hasError bool
	err      error
}

func GetProxiedClient() (*http.Client, error) {
	proxyURL := os.Getenv("ALL_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("HTTPS_PROXY")
	}

	dialer, err := proxy.SOCKS5("tcp", proxyURL, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("[GetProxiedClient] : %w", err)
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		netConn, err := dialer.Dial(network, address)
		if err == nil {
			return netConn, nil
		}

		return netConn, fmt.Errorf("[dialContext] : %w", err)
	}

	transport := &http.Transport{
		DialContext:       dialContext,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       httpClientTimeout * time.Second,
		CheckRedirect: nil,
		Jar:           nil,
	}

	return client, nil
}

// OWASP: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
func addSecureHeaders(writer *http.ResponseWriter) {
	(*writer).Header().Set("Cache-Control", "no-store")
	(*writer).Header().Set("Content-Security-Policy", "default-src https;")
	(*writer).Header().Set("Strict-Transport-Security", "max-age=63072000;")
	(*writer).Header().Set("X-Content-Type-Options", "nosniff")
	(*writer).Header().Set("X-Frame-Options", "DENY")
	(*writer).Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
}

// get price from binance.
// func getPriceFromBinance(name, unit string,
// 	wg *sync.WaitGroup,
// 	priceChan chan<- priceChanStruct,
// 	errChan chan<- errorChanStruct) {

// }

// get price from kucoin.
// func getPriceFromKu(name, uni string,
// 	wg *sync.WaitGroup,
// 	priceChan chan<- priceChanStruct,
// 	errChan chan<- errorChanStruct) {

// }

func getPriceFromCoinGecko(
	ctx context.Context,
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	priceFloat := 0.

	params := "/simple/price?ids=" + url.QueryEscape(name) + "&" +
		"vs_currencies=" + url.QueryEscape(unit)
	path := coingeckoAPIURLv3 + params

	client, err := GetProxiedClient()
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	resp, err := client.Do(req)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)
	}

	jsonBody := make(map[string]interface{})

	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)
	}

	price, isOk := jsonBody[name].(map[string]interface{})
	if !isOk {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	log.Info().Msg(string(body))

	priceFloat, isOk = price[unit].(float64)
	if !isOk {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	priceChan <- priceChanStruct{name: name, price: priceFloat}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func getPriceFromCoinCap(
	ctx context.Context,
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	priceFloat := 0.

	params := "/assets/" + url.QueryEscape(name)
	path := coincapAPIURLv2 + params

	client, err := GetProxiedClient()
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}

	resp, err := client.Do(req)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)

		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)
	}

	var coinCapAssetGetResponse CoinCapAssetGetResponse

	err = json.Unmarshal(body, &coinCapAssetGetResponse)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)
	}

	priceFloat, err = strconv.ParseFloat(coinCapAssetGetResponse.Data.PriceUsd, 64)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err)
	}

	log.Info().Msg(string(body))

	priceChan <- priceChanStruct{name: name, price: priceFloat}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func arbHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	addSecureHeaders(&w)

	var name string

	var unit string

	params := r.URL.Query()
	for key, value := range params {
		switch key {
		case "name":
			name = value[0]
		case "unit":
			unit = value[0]
		default:
			log.Error().Err(errUnexpectedParam)
		}
	}

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)

	var waitGroup sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), getTimeout*time.Second)
	defer cancel()

	waitGroup.Add(1)

	//nolint:contextcheck
	getPriceFromCoinGecko(ctx, name, unit, &waitGroup, priceChan, errChan)
	waitGroup.Wait()

	select {
	case err := <-errChan:
		if err.hasError {
			log.Error().Err(err.err)
		}
	default:
		log.Error().Err(errBadLogic)
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Error().Err(errBadLogic)
	}

	responseData := priceResponseData{
		Name:         price.name,
		Price:        price.price,
		Unit:         "USD",
		Err:          "",
		IsSuccessful: true,
	}

	jsonResp, err := json.Marshal(responseData)
	if err != nil {
		cancel()
		//nolint:gocritic
		log.Fatal().Err(err)
	}

	_, err = w.Write(jsonResp)
	if err != nil {
		cancel()
		log.Fatal().Err(err)
	}
}

func coincapHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	w.Header().Add("Content-Type", "application/json")

	addSecureHeaders(&w)

	var name string

	var unit string

	params := r.URL.Query()
	for key, value := range params {
		switch key {
		case "name":
			name = value[0]
		case "unit":
			unit = value[0]
		default:
			log.Error().Err(errUnexpectedParam)
		}
	}

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)

	var waitGroup sync.WaitGroup

	waitGroup.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), getTimeout*time.Second)
	defer cancel()

	//nolint:contextcheck
	getPriceFromCoinCap(ctx, name, unit, &waitGroup, priceChan, errChan)
	waitGroup.Wait()

	select {
	case err := <-errChan:
		if err.hasError {
			log.Error().Err(err.err)
		}
	default:
		log.Error().Err(errBadLogic)
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Error().Err(errBadLogic)
	}

	responseData := priceResponseData{
		Name:         price.name,
		Price:        price.price,
		Unit:         "USD",
		Err:          "",
		IsSuccessful: true,
	}

	jsonResp, err := json.Marshal(responseData)
	if err != nil {
		cancel()
		//nolint:gocritic
		log.Fatal().Err(err)
	}

	_, err = w.Write(jsonResp)
	if err != nil {
		cancel()
		log.Fatal().Err(err)
	}
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func startServer(gracefulWait time.Duration,
	handlers []HTTPHandler,
	serverDeploymentType string, port string,
) {
	route := mux.NewRouter()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		WriteTimeout: time.Second * serverTLSWriteTimeout,
		ReadTimeout:  time.Second * serverTLSReadTimeout,
		Handler:      route,
		TLSConfig:    cfg,
	}

	for i := 0; i < len(handlers); i++ {
		route.HandleFunc(handlers[i].name, handlers[i].function)
	}

	go func() {
		var certPath, keyPath string

		switch os.Getenv(serverDeploymentType) {
		case "deployment":
			certPath = "/certs/fullchain1.pem"
			keyPath = "/certs/privkey1.pem"
		case "test":
			certPath = "/certs/server.cert"
			keyPath = "/certs/server.key"
		default:
			log.Error().Err(errUnknownDeployment)
		}

		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil {
			log.Error().Err(err)
		}
	}()

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), gracefulWait)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err)
	}

	log.Info().Msg("gracefully shut down the server")
}

func main() {
	var gracefulWait time.Duration

	var rdb *redis.Client

	flag.DurationVar(
		&gracefulWait,
		"gracefulwait",
		time.Second*defaultGracefulShutdown,
		"the duration to wait during the graceful shutdown",
	)

	flagPort := flag.String("port", "8009", "determines the port the server will listen on")
	redisDB := flag.Int64("redisdb", 1, "determines the db number")
	redisAddress := flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword := flag.String("redispassword", "", "determines the password of the redis db")
	flag.Parse()

	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	setupLogging()

	handlerFuncs := []HTTPHandler{
		{name: "/crypto/v1/arb/gecko", function: arbHandler},
		{name: "/crypto/v1/arb/coincap", function: coincapHandler},
	}

	startServer(gracefulWait, handlerFuncs, serverDeploymentType, *flagPort)
}
