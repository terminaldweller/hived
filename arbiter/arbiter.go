package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
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
	flagPort      = flag.String("port", "8009", "determines the port the server will listen on")
	flagInterval  = flag.Float64("interval", 10, "In seconds, the delay between checking prices")
	redisDB       = flag.Int64("redisdb", 1, "determines the db number")
	rdb           *redis.Client
	redisAddress  = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword = flag.String("redispassword", "", "determines the password of the redis db")
)

const (
	SERVER_DEPLOYMENT_TYPE = "SERVER_DEPLOYMENT_TYPE"
	coingeckoAPIURLv3      = "https://api.coingecko.com/api/v3"
	coincapAPIURLv2        = "https://api.coincap.io/v2"
)

// https://docs.coincap.io/
type CoinCapAssetGetResponseData struct {
	Id                string `json:"id"`
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

type CoinCapAssetGetResponse struct {
	Data      CoinCapAssetGetResponseData `json:"data"`
	TimeStamp int64                       `json:"timestamp"`
}

type HttpHandlerFunc func(http.ResponseWriter, *http.Request)

type HttpHandler struct {
	name     string
	function HttpHandlerFunc
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
		return nil, err
	}
	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}

	transport := &http.Transport{
		DialContext:       dialContext,
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport}

	return client, nil
}

// OWASP: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
func addSecureHeaders(w *http.ResponseWriter) {
	(*w).Header().Set("Cache-Control", "no-store")
	(*w).Header().Set("Content-Security-Policy", "default-src https;")
	(*w).Header().Set("Strict-Transport-Security", "max-age=63072000;")
	(*w).Header().Set("X-Content-Type-Options", "nosniff")
	(*w).Header().Set("X-Frame-Options", "DENY")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
}

// binance
func getPriceFromBinance(name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {

}

// kucoin
func getPriceFromKu(name, uni string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {

}

func getPriceFromCoinGecko(
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {
	defer wg.Done()

	params := "/simple/price?ids=" + url.QueryEscape(name) + "&" +
		"vs_currencies=" + url.QueryEscape(unit)
	path := coingeckoAPIURLv3 + params
	fmt.Println(path)
	// resp, err := http.Get(path)
	client, err := GetProxiedClient()
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
		return
	}

	resp, err := client.Get(path)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}

	jsonBody := make(map[string]interface{})
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}

	price := jsonBody[name].(map[string]interface{})[unit].(float64)

	log.Info().Msg(string(body))

	priceChan <- priceChanStruct{name: name, price: price}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func getPriceFromCoinCap(
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {
	defer wg.Done()

	params := "/assets/" + url.QueryEscape(name)
	path := coincapAPIURLv2 + params
	fmt.Println(path)
	client, err := GetProxiedClient()
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
		return
	}
	// resp, err := http.Get(path)
	resp, err := client.Get(path)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}
	fmt.Println(string(body))

	var coinCapAssetGetResponse CoinCapAssetGetResponse
	// jsonBody := make(map[string]interface{})
	// err = json.Unmarshal(body, &jsonBody)
	err = json.Unmarshal(body, &coinCapAssetGetResponse)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}

	// price := jsonBody[name].(map[string]interface{})[unit].(float64)
	price, err := strconv.ParseFloat(coinCapAssetGetResponse.Data.PriceUsd, 64)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}
	fmt.Println(price)

	log.Info().Msg(string(body))

	priceChan <- priceChanStruct{name: name, price: price}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func arbHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
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
			log.Error().Err(errors.New("Got unexpected parameter."))
		}
	}

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	getPriceFromCoinGecko(name, unit, &wg, priceChan, errChan)
	wg.Wait()

	select {
	case err := <-errChan:
		if err.hasError != false {
			log.Error().Err(err.err)
		}
	default:
		log.Error().Err(errors.New("We shouldnt be here"))
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Fatal().Err(errors.New("We shouldnt be here"))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":         price.name,
		"price":        price.price,
		"unit":         unit,
		"err":          "",
		"isSuccessful": true,
	})
}

func coincapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
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
			log.Error().Err(errors.New("Got unexpected parameter."))
		}
	}

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	getPriceFromCoinCap(name, unit, &wg, priceChan, errChan)
	wg.Wait()

	select {
	case err := <-errChan:
		if err.hasError != false {
			log.Error().Err(err.err)
		}
	default:
		log.Error().Err(errors.New("We shouldnt be here"))
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Fatal().Err(errors.New("We shouldnt be here"))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":         price.name,
		"price":        price.price,
		"unit":         "USD",
		"err":          "",
		"isSuccessful": true,
	})
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func startServer(gracefulWait time.Duration,
	handlers []HttpHandler,
	serverDeploymentType string, port string) {
	r := mux.NewRouter()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		Handler:      r,
		TLSConfig:    cfg,
	}

	for i := 0; i < len(handlers); i++ {
		r.HandleFunc(handlers[i].name, handlers[i].function)
	}

	go func() {
		var certPath, keyPath string
		if os.Getenv(serverDeploymentType) == "deployment" {
			certPath = "/certs/fullchain1.pem"
			keyPath = "/certs/privkey1.pem"
		} else if os.Getenv(serverDeploymentType) == "test" {
			certPath = "/certs/server.cert"
			keyPath = "/certs/server.key"
		} else {
			log.Fatal().Err(errors.New(fmt.Sprintf("unknown deployment kind: %s", serverDeploymentType)))
		}
		if err := srv.ListenAndServeTLS(certPath, keyPath); err != nil {
			log.Fatal().Err(err)
		}
	}()

	c := make(chan os.Signal, 1)

	signal.Notify(c, os.Interrupt)
	<-c
	ctx, cancel := context.WithTimeout(context.Background(), gracefulWait)
	defer cancel()
	srv.Shutdown(ctx)
	log.Info().Msg("gracefully shut down the server")
}

func main() {
	var gracefulWait time.Duration
	flag.DurationVar(&gracefulWait, "gracefulwait", time.Second*15, "the duration to wait during the graceful shutdown")
	flag.Parse()
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	setupLogging()
	var handlerFuncs = []HttpHandler{
		{name: "/crypto/v1/arb/gecko", function: arbHandler},
		{name: "/crypto/v1/arb/coincap", function: coincapHandler},
	}

	startServer(gracefulWait, handlerFuncs, SERVER_DEPLOYMENT_TYPE, *flagPort)
}
