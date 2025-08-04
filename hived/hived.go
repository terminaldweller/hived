package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Knetic/govaluate"
	"github.com/go-redis/redis/v8"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models/schema"
	"github.com/pocketbase/pocketbase/plugins/ghupdate"
	"github.com/pocketbase/pocketbase/plugins/jsvm"
	"github.com/pocketbase/pocketbase/plugins/migratecmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

const (
	cryptocomparePriceURL        = "https://min-api.cryptocompare.com/data/price?"
	polygonCryptoTickerURL       = "https://api.polygon.io/v2/snapshot/locale/global/markets/crypto/tickers"
	cmcCryptoTickerURL           = "https://pro-api.coinmarketcap.com/v2/cryptocurrency/quotes/latest"
	coingeckoAPIURLv3            = "https://api.coingecko.com/api/v3"
	coincapAPIURLv2              = "https://api.coincap.io/v2"
	httpClientTimeout            = 5
	getTimeout                   = 5
	serverTLSReadTimeout         = 15
	serverTLSWriteTimeout        = 15
	defaultGracefulShutdown      = 15
	redisContextTimeout          = 2
	pingTimeout                  = 5
	alertCheckIntervalDefault    = 600
	tickerCheckIntervalDefault   = 600
	redisCacheDurationMultiplier = 1_000_000
	cacheDurationdefault         = 300_000
	telegramTimeout              = 10
	// coingeckoAPIURLv3            = "https://api.coingecko.com/api/v3"
)

var (
	cacheDuration = flag.Float64(
		"cacheDuration",
		cacheDurationdefault,
		"determines the price cache validity duration in miliseconds",
	)
	rdb                      *redis.Client
	errUnknownParam          = errors.New("unknown parameters for endpoint")
	errIncompParams          = errors.New("incomplete set of parameters")
	errBadLogic              = errors.New("bad logic")
	errFailedTypeAssertion   = errors.New("type assertion failed")
	errFailedUnmarshall      = errors.New("failed to unmarshall JSON")
	errUnknownDeploymentKind = errors.New("unknown deployment kind")
)

type HivedConfig struct {
	KeydbAddress        string `toml:"keydbAddress"`
	KeydbPassword       string `toml:"keydbPassword"`
	KeydbDB             int    `toml:"keydbDB"`
	AlertsCheckInterval int64  `toml:"alertsCheckInterval"`
	TickerCheckInterval int64  `toml:"tickerCheckInterval"`
	CacheDuration       int64  `toml:"cacheDuration"`
	TelegramChannelID   int64  `toml:"telegramChannelID"`
	TelegramBotToken    string `toml:"telegramBotToken"`
}

type appWrapper struct {
	app *pocketbase.PocketBase
}

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

type RootCmds struct {
	hooksDir      string
	hooksWatch    bool
	hooksPool     int
	hooksPoolSize int
	migrationsDir string
	automigrate   bool
	publicDir     string
	indexFallback bool
	queryTimeout  int
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

func getTGBot(tgtoken string) *tgbotapi.BotAPI {
	bot, err := tgbotapi.NewBotAPI(tgtoken)
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	return bot
}

func sendMessage(bot *tgbotapi.BotAPI, msgText string, channelID int64) error {
	msg := tgbotapi.NewMessage(channelID, msgText)
	_, err := bot.Send(msg)

	return err
}

func GetProxiedClient() *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             http.ProxyFromEnvironment,
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       httpClientTimeout * time.Second,
		CheckRedirect: nil,
		Jar:           nil,
	}

	return client
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

func (cw HivedConfig) sendToTg(msg string) {
	tgbotapi := getTGBot(cw.TelegramBotToken)

	err := sendMessage(tgbotapi, msg, cw.TelegramChannelID)
	if err != nil {
		log.Info().Err(err)
	}
}

type priceChanStruct struct {
	name  string
	price float64
}

type errorChanStruct struct {
	hasError bool
	err      error
}

func getPrice(ctx context.Context,
	name, unit string,
	waitGroup *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	val, err := rdb.Get(ctx, name+"_price").Float64()

	if err != nil {
		source := os.Getenv("HIVED_PRICE_SOURCE")

		switch source {
		case "cryptocompare":
			getPriceFromCryptoCompare(ctx, name, unit, waitGroup, priceChan, errChan)
		case "polygon":
			getPriceFromPolygon(ctx, name, waitGroup, priceChan, errChan)
		case "cmc":
			getPriceFromCMC(ctx, name, waitGroup, priceChan, errChan)
		}
	} else {
		priceChan <- priceChanStruct{name: name, price: val}
		errChan <- errorChanStruct{hasError: false, err: nil}

		waitGroup.Done()
	}
}

func getPriceFromCryptoCompareErrorHandler(
	err error,
	name string,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defaultPrice := 0.
	priceChan <- priceChanStruct{name: name, price: defaultPrice}
	errChan <- errorChanStruct{hasError: true, err: err}

	log.Error().Err(err).Send()
}

func getPriceFromCryptoCompare(
	ctx context.Context,
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	params := "fsym=" + url.QueryEscape(name) + "&" +
		"tsyms=" + url.QueryEscape(unit)
	path := cryptocomparePriceURL + params

	log.Print(path)

	client := GetProxiedClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}

	apiKey := os.Getenv("CRYPTOCOMPARE_API_KEY")

	req.Header.Set("Apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}
	defer resp.Body.Close()

	jsonBody := make(map[string]float64)

	err = json.NewDecoder(resp.Body).Decode(&jsonBody)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)
	}

	// add a price cache
	err = rdb.Set(ctx, name+"_price", jsonBody[unit], time.Duration(*cacheDuration*redisCacheDurationMultiplier)).Err()
	if err != nil {
		log.Error().Err(err)
	}

	priceChan <- priceChanStruct{name: name, price: jsonBody[unit]}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func getPriceFromPolygon(
	ctx context.Context,
	name string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	apiKey := os.Getenv("POLYGON_API_KEY")

	params := "/" + name + "?" +
		"apiKey=" + url.QueryEscape(apiKey)
	path := polygonCryptoTickerURL + params

	log.Print(path)

	client := GetProxiedClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}

	resp, err := client.Do(req)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}
	defer resp.Body.Close()

	var jsonBody PolygonTickerResponse

	err = json.NewDecoder(resp.Body).Decode(&jsonBody)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)
	}

	log.Print(jsonBody)

	price := jsonBody.Ticker.Min.O

	// add a price cache
	err = rdb.Set(ctx, name+"_price", price, time.Duration(*cacheDuration*redisCacheDurationMultiplier)).Err()
	if err != nil {
		log.Error().Err(err)
	}

	priceChan <- priceChanStruct{name: name, price: price}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func getPriceFromCMC(
	ctx context.Context,
	name string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	apiKey := os.Getenv("CMC_API_KEY")

	params := "?slug=" + name
	path := cmcCryptoTickerURL + params

	log.Print(path)

	client := GetProxiedClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}

	req.Header.Set("X-CMC_PRO_API_KEY", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}
	defer resp.Body.Close()

	var jsonBody CMCTickerResponseType

	err = json.NewDecoder(resp.Body).Decode(&jsonBody)
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)
	}

	log.Print(jsonBody)

	var price float64
	for _, v := range jsonBody.Data {
		price = v.Quote["USD"].Price
	}

	err = rdb.Set(ctx, name+"_price", price, time.Duration(*cacheDuration*redisCacheDurationMultiplier)).Err()
	if err != nil {
		log.Error().Err(err)
	}

	priceChan <- priceChanStruct{name: name, price: price}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func GetPriceFromCoinGecko(
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

	client := GetProxiedClient()

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

		log.Error().Err(err).Send()

		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err).Send()
	}

	jsonBody := make(map[string]interface{})

	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err).Send()
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

func GetPriceFromCoinCap(
	ctx context.Context,
	name string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	defer wg.Done()

	priceFloat := 0.

	params := "/assets/" + url.QueryEscape(name)
	path := coincapAPIURLv2 + params

	client := GetProxiedClient()

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

		log.Error().Err(err).Send()

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

		log.Error().Err(err).Send()
	}

	priceFloat, err = strconv.ParseFloat(coinCapAssetGetResponse.Data.PriceUsd, 64)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: priceFloat}
		errChan <- errorChanStruct{hasError: true, err: err}

		log.Error().Err(err).Send()
	}

	log.Info().Msg(string(body))

	priceChan <- priceChanStruct{name: name, price: priceFloat}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func (aw appWrapper) PriceHandler(echoCtx echo.Context) error {
	writer := echoCtx.Response().Writer
	request := echoCtx.Request()
	writer.Header().Add("Content-Type", "application/json")

	if request.Method != http.MethodGet {
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}

	addSecureHeaders(&writer)

	var name string

	var unit string

	params := request.URL.Query()
	for key, value := range params {
		switch key {
		case "name":
			name = value[0]
		case "unit":
			unit = value[0]
		default:
			log.Error().Err(errUnknownParam)
		}
	}

	if name == "" || unit == "" {
		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"err":          "query parameters must include name and unit",
			"isSuccessful": false,
		})
		if err != nil {
			log.Error().Err(errIncompParams)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}

		return nil
	}

	var waitGroup sync.WaitGroup

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)

	defer close(errChan)
	defer close(priceChan)
	waitGroup.Add(1)

	ctx, cancel := context.WithTimeout(request.Context(), getTimeout*time.Second)
	defer cancel()

	go getPrice(ctx, name, unit, &waitGroup, priceChan, errChan)

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

	err := json.NewEncoder(writer).Encode(map[string]interface{}{
		"name":         price.name,
		"price":        price.price,
		"unit":         unit,
		"err":          "",
		"isSuccessful": true,
	})
	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)

		return err
	}

	return nil
}

func (aw appWrapper) PairHandler(echoCtx echo.Context) error {
	var err error

	writer := echoCtx.Response().Writer
	request := echoCtx.Request()

	writer.Header().Add("Content-Type", "application/json")

	if request.Method != http.MethodGet {
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}

	addSecureHeaders(&writer)

	var one string

	var two string

	var multiplier float64

	params := request.URL.Query()
	for key, value := range params {
		switch key {
		case "one":
			one = value[0]
		case "two":
			two = value[0]
		case "multiplier":
			multiplier, err = strconv.ParseFloat(value[0], 64)
			if err != nil {
				log.Fatal().Err(err)
			}
		default:
			log.Fatal().Err(errUnknownParam)
		}
	}

	if one == "" || two == "" || multiplier == 0. {
		log.Error().Err(errIncompParams)
	}

	var waitGroup sync.WaitGroup

	priceChan := make(chan priceChanStruct, 2) //nolint: mnd,gomnd
	errChan := make(chan errorChanStruct, 2)   //nolint: mnd,gomnd

	defer close(priceChan)
	defer close(errChan)

	ctx, cancel := context.WithTimeout(request.Context(), getTimeout*time.Second)
	defer cancel()

	waitGroup.Add(2) //nolint: mnd,gomnd

	go getPrice(ctx, one, "USD", &waitGroup, priceChan, errChan)
	go getPrice(ctx, two, "USD", &waitGroup, priceChan, errChan)

	waitGroup.Wait()

	for range 2 {
		select {
		case err := <-errChan:
			if err.hasError {
				log.Error().Err(err.err)
			}
		default:
			log.Error().Err(errBadLogic)
		}
	}

	var priceOne float64

	var priceTwo float64

	for range 2 {
		select {
		case price := <-priceChan:
			if price.name == one {
				priceOne = price.price
			}

			if price.name == two {
				priceTwo = price.price
			}
		default:
			log.Error().Err(errBadLogic)
		}
	}

	ratio := priceOne * multiplier / priceTwo

	log.Info().Msg(fmt.Sprintf("%v", ratio))

	err = json.NewEncoder(writer).Encode(map[string]interface{}{"ratio": ratio})
	if err != nil {
		log.Error().Err(err).Send()
		http.Error(writer, "internal server error", http.StatusInternalServerError)

		return err
	}

	return nil
}

type alertType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

type alertsType struct {
	Alerts []alertType `json:"alerts"`
}

type tickerType struct {
	Name string `json:"name"`
}

type tickersType struct {
	Tickers []tickerType `json:"tickers"`
}

func getAlerts() alertsType {
	var alerts alertsType

	ctx := context.Background()
	keys := rdb.SMembersMap(ctx, "alertkeys")
	alerts.Alerts = make([]alertType, len(keys.Val()))
	vals := keys.Val()

	alertIndex := 0

	for key := range vals {
		alert := rdb.Get(ctx, key[6:])
		expr, _ := alert.Result()
		alerts.Alerts[alertIndex].Name = key
		alerts.Alerts[alertIndex].Expr = expr
		alertIndex++
	}

	return alerts
}

func getTickers() tickersType {
	var tickers tickersType

	ctx := context.Background()
	keys := rdb.SMembersMap(ctx, "tickerkeys")
	tickers.Tickers = make([]tickerType, len(keys.Val()))
	vals := keys.Val()

	tickerIndex := 0

	for key := range vals {
		tickers.Tickers[tickerIndex].Name = key[7:]
		tickerIndex++
	}

	return tickers
}

func alertManagerWorker(alert alertType, config HivedConfig) {
	expression, err := govaluate.NewEvaluableExpression(alert.Expr)
	if err != nil {
		log.Error().Err(err)
	}

	vars := expression.Vars()
	parameters := make(map[string]interface{}, len(vars))

	var waitGroup sync.WaitGroup

	priceChan := make(chan priceChanStruct, len(vars))
	defer close(priceChan)

	errChan := make(chan errorChanStruct, len(vars))
	defer close(errChan)

	ctx, cancel := context.WithTimeout(context.Background(), getTimeout*time.Second)
	defer cancel()

	waitGroup.Add(len(vars))

	for i := range vars {
		go getPrice(ctx, vars[i], "USD", &waitGroup, priceChan, errChan)
	}

	waitGroup.Wait()

	for range len(vars) {
		select {
		case err := <-errChan:
			if err.hasError {
				log.Printf(err.err.Error())
			}
		default:
			log.Error().Err(errBadLogic).Send()
		}
	}

	for range len(vars) {
		select {
		case price := <-priceChan:
			parameters[price.name] = price.price
		default:
			log.Error().Err(errBadLogic)
		}
	}

	log.Info().Msg(fmt.Sprintf("parameters: %v", parameters))

	result, err := expression.Evaluate(parameters)
	if err != nil {
		log.Error().Err(err)
	}

	var resultBool bool

	log.Info().Msg(fmt.Sprintf("result: %v", result))

	resultBool, ok := result.(bool)
	if !ok {
		log.Error().Err(errFailedTypeAssertion)

		return
	}

	if !resultBool {
		return
	}

	msgText := "notification " + alert.Expr + " has been triggered"

	if err == nil {
		log.Error().Err(err)
	}

	config.sendToTg(msgText)
}

func alertManager(config HivedConfig) {
	for {
		alerts := getAlerts()

		log.Info().Msg(fmt.Sprintf("%v", alerts))

		for alertIndex := range alerts.Alerts {
			go alertManagerWorker(alerts.Alerts[alertIndex], config)
		}

		time.Sleep(time.Second * time.Duration(config.AlertsCheckInterval))
	}
}

func tickerManager(config HivedConfig) {
	for {
		tickers := getTickers()

		log.Info().Msg(fmt.Sprintf("%v", tickers))

		for tickerIndex := range tickers.Tickers {
			go tickerManagerWorker(tickers.Tickers[tickerIndex], config)
		}

		time.Sleep(time.Second * time.Duration(config.TickerCheckInterval))
	}
}

func tickerManagerWorker(ticker tickerType, config HivedConfig) {
	var waitGroup sync.WaitGroup

	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)

	defer close(errChan)
	defer close(priceChan)
	waitGroup.Add(1)

	ctx, cancel := context.WithTimeout(context.Background(), getTimeout*time.Second)
	defer cancel()

	go getPrice(ctx, ticker.Name, "USD", &waitGroup, priceChan, errChan)

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

	msgText := "ticker: " + ticker.Name + ":" + strconv.FormatFloat(price.price, 'f', -1, 64)

	log.Print(msgText)

	config.sendToTg(msgText)
}

type addAlertJSONType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

type tickerJSONType struct {
	Name string `json:"name"`
}

func (aw appWrapper) tickerHandler(echoCtx echo.Context) error {
	writer := echoCtx.Response().Writer
	request := echoCtx.Request()

	addSecureHeaders(&writer)

	handler := Handler{rdb: rdb}

	switch request.Method {
	case http.MethodPost:
		handler.HandleTickerPost(writer, request)
	case http.MethodPut:
		handler.HandleTickerPost(writer, request)
	case http.MethodPatch:
		handler.HandleTickerPost(writer, request)
	case http.MethodDelete:
		handler.HandleTickerDelete(writer, request)
	case http.MethodGet:
		handler.HandleTickerGet(writer, request)
	default:
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}

	return nil
}

func (aw appWrapper) healthHandler(echoCtx echo.Context) error {
	writer := echoCtx.Response().Writer
	request := echoCtx.Request()
	var RedisError string

	var HivedError string

	var IsRedisOk bool

	IsHivedOk := true

	addSecureHeaders(&writer)
	writer.Header().Add("Content-Type", "application/json")

	if request.Method != http.MethodGet {
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}

	ctx, cancel := context.WithTimeout(request.Context(), pingTimeout*time.Second)
	defer cancel()

	pingResponse := rdb.Ping(ctx)

	pingResponseResult, err := pingResponse.Result()
	if err != nil {
		log.Err(err)

		IsRedisOk = false
		RedisError = err.Error()
	} else {
		if pingResponseResult == "PONG" {
			IsRedisOk = true
			RedisError = ""
		} else {
			IsRedisOk = false
			RedisError = "redis did not respond PONG to ping"
		}
	}

	writer.WriteHeader(http.StatusOK)

	err = json.NewEncoder(writer).Encode(map[string]interface{}{
		"isHivedOk":  IsHivedOk,
		"hivedError": HivedError,
		"isRedisOk":  IsRedisOk,
		"redisError": RedisError,
	})

	if request.Method != http.MethodGet {
		http.Error(writer, "internal server error", http.StatusInternalServerError)
		log.Error().Err(err)

		return err
	}

	return nil
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func (aw appWrapper) postHandler(context echo.Context) error {
	user, pass, ok := context.Request().BasicAuth()
	if !ok {
		return context.JSON(http.StatusUnauthorized, "unauthorized") //nolint: wrapcheck
	}

	userRecord, err := aw.app.Dao().FindAuthRecordByUsername("users", user)
	if err != nil {
		return context.JSON(http.StatusUnauthorized, "unauthorized") //nolint: wrapcheck
	}

	if !userRecord.ValidatePassword(pass) {
		return context.JSON(http.StatusUnauthorized, "unauthorized") //nolint: wrapcheck
	}

	return context.JSON(http.StatusOK, "OK") //nolint: wrapcheck
}

func defaultPublicDir() string {
	if strings.HasPrefix(os.Args[0], os.TempDir()) {
		return "./pb_public"
	}

	return filepath.Join(os.Args[0], "../pb_public")
}

func (aw appWrapper) apikeyAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		apikey := c.Request().Header["X-Apikey"][0]
		user := c.Request().Header["X-User"][0]

		userRecord, err := aw.app.Dao().FindAuthRecordByUsername("users", user)
		if err != nil {
			return apis.NewBadRequestError("unauthorized", nil)
		}

		hashedAPIKey := userRecord.Get("apikey")

		hashedAPIKeyStr, ok := hashedAPIKey.(string)
		if !ok {
			return apis.NewBadRequestError("unauthorized", nil)
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedAPIKeyStr), []byte(apikey))
		if err != nil {
			log.Print("apikey auth failed for user: " + user)
			return apis.NewBadRequestError("unauthorized", nil)
		}

		return next(c)
	}
}

func (aw appWrapper) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, pass, ok := c.Request().BasicAuth()
		if !ok {
			return apis.NewBadRequestError("unauthorized", nil)
		}

		userRecord, err := aw.app.Dao().FindAuthRecordByUsername("users", user)
		if err != nil {
			log.Print(err)
			return apis.NewBadRequestError("unauthorized", nil)
		}

		if !userRecord.ValidatePassword(pass) {
			return apis.NewBadRequestError("unauthorized", nil)
		}

		return next(c)
	}
}

func setRootCmds(app *pocketbase.PocketBase) RootCmds {
	var rootCmds RootCmds

	app.RootCmd.PersistentFlags().StringVar(
		&rootCmds.hooksDir,
		"hooksDir",
		"",
		"the directory with the JS app hooks",
	)

	app.RootCmd.PersistentFlags().BoolVar(
		&rootCmds.hooksWatch,
		"hooksWatch",
		true,
		"auto restart the app on pb_hooks file change",
	)

	app.RootCmd.PersistentFlags().IntVar(
		&rootCmds.hooksPool,
		"hooksPool",
		25,
		"the total prewarm goja.Runtime instances for the JS app hooks execution",
	)

	app.RootCmd.PersistentFlags().StringVar(
		&rootCmds.migrationsDir,
		"migrationsDir",
		"",
		"the directory with the user defined migrations",
	)

	app.RootCmd.PersistentFlags().BoolVar(
		&rootCmds.automigrate,
		"automigrate",
		true,
		"enable/disable auto migrations",
	)

	app.RootCmd.PersistentFlags().StringVar(
		&rootCmds.publicDir,
		"publicDir",
		defaultPublicDir(),
		"the directory to serve static files",
	)

	app.RootCmd.PersistentFlags().BoolVar(
		&rootCmds.indexFallback,
		"indexFallback",
		true,
		"fallback the request to index.html on missing static path (eg. when pretty urls are used with SPA)",
	)

	app.RootCmd.PersistentFlags().IntVar(
		&rootCmds.queryTimeout,
		"queryTimeout",
		30,
		"the default SELECT queries timeout in seconds",
	)

	return rootCmds
}

func startPocketbaseApp() {
	app := pocketbase.New()

	aw := appWrapper{app: app}

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		e.Router.POST("/", aw.postHandler, aw.apikeyAuthMiddleware)
		e.Router.GET("/health", aw.healthHandler, aw.apikeyAuthMiddleware)
		e.Router.GET("/api/crypto/v1/price", aw.PriceHandler, aw.apikeyAuthMiddleware)
		e.Router.GET("/api/crypto/v1/pair", aw.PairHandler, aw.apikeyAuthMiddleware)

		e.Router.GET("/api/crypto/v1/alert", aw.alertHandler, aw.apikeyAuthMiddleware)
		e.Router.PUT("/api/crypto/v1/alert", aw.alertHandler, aw.apikeyAuthMiddleware)
		e.Router.POST("/api/crypto/v1/alert", aw.alertHandler, aw.apikeyAuthMiddleware)
		e.Router.PATCH("/api/crypto/v1/alert", aw.alertHandler, aw.apikeyAuthMiddleware)
		e.Router.DELETE("/api/crypto/v1/alert", aw.alertHandler, aw.apikeyAuthMiddleware)

		e.Router.GET("/api/crypto/v1/ticker", aw.tickerHandler, aw.apikeyAuthMiddleware)
		e.Router.PUT("/api/crypto/v1/ticker", aw.tickerHandler, aw.apikeyAuthMiddleware)
		e.Router.POST("/api/crypto/v1/ticker", aw.tickerHandler, aw.apikeyAuthMiddleware)
		e.Router.PATCH("/api/crypto/v1/ticker", aw.tickerHandler, aw.apikeyAuthMiddleware)
		e.Router.DELETE("/api/crypto/v1/ticker", aw.tickerHandler, aw.apikeyAuthMiddleware)

		return nil
	})

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		dao := app.Dao()

		collection, err := dao.FindCollectionByNameOrId("users")
		if err != nil {
			log.Fatal().Err(err).Msg("failed to find users collection")
		}

		if field := collection.Schema.GetFieldByName("apikey"); field == nil {
			newField := &schema.SchemaField{
				Name:     "apikey",
				Type:     schema.FieldTypeText,
				System:   false,
				Required: false,
				Unique:   true,
			}

			collection.Schema.AddField(newField)

			if err := dao.SaveCollection(collection); err != nil {
				log.Fatal().Err(err).Msg("failed to save users collection with apikey field")
			}
		}

		return nil
	})

	app.OnRecordBeforeCreateRequest("users").Add(func(e *core.RecordCreateEvent) error {
		apikeyHash, err := GenAPIKey()
		if err != nil {
			return err
		}

		e.Record.Set("apikey", apikeyHash)
		return nil
	})

	rootCmds := setRootCmds(app)

	err := app.RootCmd.ParseFlags(os.Args[1:])
	if err != nil {
		log.Fatal().Err(err)
	}

	jsvm.MustRegister(app, jsvm.Config{
		MigrationsDir: rootCmds.migrationsDir,
		HooksDir:      rootCmds.hooksDir,
		HooksWatch:    rootCmds.hooksWatch,
		HooksPoolSize: rootCmds.hooksPoolSize,
	})

	migratecmd.MustRegister(app, app.RootCmd, migratecmd.Config{
		TemplateLang: migratecmd.TemplateLangJS,
		Automigrate:  rootCmds.automigrate,
		Dir:          rootCmds.migrationsDir,
	})

	ghupdate.MustRegister(app, app.RootCmd, ghupdate.Config{})

	app.OnAfterBootstrap().PreAdd(func(_ *core.BootstrapEvent) error {
		app.Dao().ModelQueryTimeout = time.Duration(rootCmds.queryTimeout) * time.Second

		return nil
	})

	app.OnBeforeServe().Add(func(e *core.ServeEvent) error {
		e.Router.GET("/*", apis.StaticDirectoryHandler(os.DirFS(rootCmds.publicDir), rootCmds.indexFallback))

		return nil
	})

	if err := app.Start(); err != nil {
		log.Fatal().Err(err)
	}
}

func main() {
	configPathFlag := flag.String("config", "/hived/hived.toml", "path to the hived config file")
	flag.Parse()
	data, err := os.ReadFile(*configPathFlag)
	if err != nil {
		log.Fatal().Err(err)
	}

	var config HivedConfig

	_, err = toml.Decode(string(data), &config)
	if err != nil {
		log.Fatal().Err(err)
	}

	fmt.Println("config:", config)

	rdb = redis.NewClient(&redis.Options{
		Addr:     config.KeydbAddress,
		Password: config.KeydbPassword,
		DB:       config.KeydbDB,
	})
	defer rdb.Close()

	setupLogging()

	go alertManager(config)

	go tickerManager(config)

	startPocketbaseApp()
}
