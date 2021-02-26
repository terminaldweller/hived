package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/go-redis/redis/v8"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var flagPort = flag.String("port", "8008", "determined the port the sercice runs on")

var alertsCheckInterval = flag.Int64("alertinterval", 600., "in seconds, the amount of time between alert checks")
var redisAddress = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
var redisPassword = flag.String("redispassword", "", "determines the password of the redis db")
var redisDB = flag.Int64("redisdb", 0, "determines the db number")
var botChannelID = flag.Int64("botchannelid", 146328407, "determines the channel id the telgram bot should send messages to")

const cryptocomparePriceURL = "https://min-api.cryptocompare.com/data/price?"
const changellyURL = "https://api.changelly.com"
const TELEGRAM_BOT_TOKEN_ENV_VAR = "TELEGRAM_BOT_TOKEN"
const CHANGELLY_API_KEY_ENV_VAR = "CHANGELLY_API_KEY"
const CHANGELLY_API_SECRET_ENV_VAR = "CHANGELLY_API_SECRET"

var getRedisClientOnce sync.Once
var getTGBotOnce sync.Once

func runTgBot() {
	// bot := getTgBot()
	token := os.Getenv(TELEGRAM_BOT_TOKEN_ENV_VAR)
	bot, err := tgbotapi.NewBotAPI(token[1 : len(token)-1])
	if err != nil {
		log.Error().Err(err)
	}
	log.Debug().Msg("authorized on account bot_bloodstalker")

	update := tgbotapi.NewUpdate(0)
	update.Timeout = 60

	updates, err := bot.GetUpdatesChan(update)
	if err != nil {
		log.Error().Err(err)
	}

	for update := range updates {
		if update.Message == nil {
			continue
		}

		log.Printf("[%s] %s", update.Message.From.UserName, update.Message.Text)

		msg := tgbotapi.NewMessage(update.Message.Chat.ID, update.Message.Text)
		msg.ReplyToMessageID = update.Message.MessageID

		bot.Send(msg)
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

func sendGetToCryptoCompare(
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {
	defer wg.Done()

	params := "fsym=" + url.QueryEscape(name) + "&" +
		"tsyms=" + url.QueryEscape(unit)
	path := cryptocomparePriceURL + params
	fmt.Println(path)
	resp, err := http.Get(path)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		fmt.Println(err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		fmt.Println(err.Error())
	}

	jsonBody := make(map[string]float64)
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		fmt.Println(err.Error())
	}

	fmt.Println(string(body))

	priceChan <- priceChanStruct{name: name, price: jsonBody[unit]}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func priceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

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
			log.Error().Err(errors.New("bad parameters for the crypto endpoint."))
		}
	}

	if name == "" || unit == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"err":          "query parameters must include name and unit",
			"isSuccessful": false})
		log.Error().Err(errors.New("query parameters must include name and unit."))
		return
	}

	var wg sync.WaitGroup
	priceChan := make(chan priceChanStruct, 1)
	errChan := make(chan errorChanStruct, 1)
	defer close(errChan)
	defer close(priceChan)
	wg.Add(1)
	go sendGetToCryptoCompare(name, unit, &wg, priceChan, errChan)
	wg.Wait()

	select {
	case err := <-errChan:
		if err.hasError != false {
			log.Error().Err(err.err)
		}
	default:
		log.Error().Err(errors.New("this shouldn't have happened'"))
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Fatal().Err(errors.New("this shouldnt have happened"))
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"name":         price.name,
		"price":        price.price,
		"unit":         unit,
		"err":          "",
		"isSuccessful": true})
}

func pairHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	var one string
	var two string
	var multiplier float64
	params := r.URL.Query()
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
			log.Fatal().Err(errors.New("unknown parameters for the pair endpoint."))
		}
	}

	if one == "" || two == "" || multiplier == 0. {
		log.Error().Err(errors.New("the query must include one()),two and multiplier"))
	}

	var wg sync.WaitGroup
	priceChan := make(chan priceChanStruct, 2)
	errChan := make(chan errorChanStruct, 2)
	defer close(priceChan)
	defer close(errChan)

	wg.Add(2)
	go sendGetToCryptoCompare(one, "USD", &wg, priceChan, errChan)
	go sendGetToCryptoCompare(two, "USD", &wg, priceChan, errChan)
	wg.Wait()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errChan:
			if err.hasError != false {
				log.Error().Err(err.err)
			}
		default:
			log.Fatal().Err(errors.New("this shouldnt have happened"))
		}
	}

	var priceOne float64
	var priceTwo float64
	for i := 0; i < 2; i++ {
		select {
		case price := <-priceChan:
			if price.name == one {
				priceOne = price.price
			}
			if price.name == two {
				priceTwo = price.price
			}
		default:
			log.Fatal().Err(errors.New("this shouldnt have happened"))
		}
	}

	ratio := priceOne * multiplier / priceTwo
	fmt.Println(ratio)
	json.NewEncoder(w).Encode(map[string]interface{}{"ratio": ratio})
}

type alertType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

type alertsType struct {
	Alerts []alertType `json:"alerts"`
}

//FIXME
func getRedisClient() *redis.Client {
	var client *redis.Client
	getRedisClientOnce.Do(func() {
		rdb := redis.NewClient(&redis.Options{
			Addr:     *redisAddress,
			Password: *redisPassword,
			DB:       int(*redisDB),
		})
		client = rdb
	})

	return client
}

func getAlerts() (alertsType, error) {
	var alerts alertsType
	// rdb := getRedisClient()
	rdb := redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	ctx := context.Background()
	keys := rdb.SMembersMap(ctx, "alertkeys")
	alerts.Alerts = make([]alertType, len(keys.Val()))
	vals := keys.Val()

	i := 0
	for key := range vals {
		alert := rdb.Get(ctx, key[6:])
		expr, _ := alert.Result()
		alerts.Alerts[i].Name = key
		alerts.Alerts[i].Expr = expr
		i++
	}

	return alerts, nil
}

//not being used
func getAlertsFromRedis() (alertsType, error) {
	// rdb := getRedisClient()
	rdb := redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	ctx := context.Background()
	val, err := rdb.Get(ctx, "alert").Result()
	if err != nil {
		log.Error().Err(err)
		return alertsType{}, err
	}
	fmt.Println(val)

	err = rdb.Close()
	if err != nil {
		log.Error().Err(err)
	}

	return alertsType{}, nil
}

func alertManager() {
	for {
		alerts, err := getAlerts()
		if err != nil {
			log.Error().Err(err)
			return
		}
		fmt.Println(alerts)

		for i := range alerts.Alerts {
			expression, err := govaluate.NewEvaluableExpression(alerts.Alerts[i].Expr)
			if err != nil {
				log.Error().Err(err)
				continue
			}

			vars := expression.Vars()
			parameters := make(map[string]interface{}, len(vars))

			var wg sync.WaitGroup
			priceChan := make(chan priceChanStruct, len(vars))
			errChan := make(chan errorChanStruct, len(vars))
			defer close(priceChan)
			defer close(errChan)
			wg.Add(len(vars))

			for i := range vars {
				go sendGetToCryptoCompare(vars[i], "USD", &wg, priceChan, errChan)
			}
			wg.Wait()

			for i := 0; i < len(vars); i++ {
				select {
				case err := <-errChan:
					if err.hasError != false {
						log.Printf(err.err.Error())
					}
				default:
					log.Error().Err(errors.New("this shouldnt have happened"))
				}
			}

			for i := 0; i < len(vars); i++ {
				select {
				case price := <-priceChan:
					parameters[price.name] = price.price
				default:
					log.Error().Err(errors.New("this shouldnt have happened"))
				}
			}

			fmt.Println("parameters:", parameters)
			result, err := expression.Evaluate(parameters)
			if err != nil {
				log.Error().Err(err)
			}

			var resultBool bool
			fmt.Println("result:", result)
			resultBool = result.(bool)
			if resultBool == true {
				// bot := getTgBot()
				token := os.Getenv(TELEGRAM_BOT_TOKEN_ENV_VAR)
				bot, err := tgbotapi.NewBotAPI(token[1 : len(token)-1])
				if err != nil {
					log.Error().Err(err)
				}
				msgText := "notification " + alerts.Alerts[i].Expr + " has been triggered"
				msg := tgbotapi.NewMessage(*botChannelID, msgText)
				bot.Send(msg)
			}
		}

		time.Sleep(time.Second * time.Duration(*alertsCheckInterval))
	}
}

type addAlertJSONType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

func handleAlertPost(w http.ResponseWriter, r *http.Request) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf(err.Error())
	}

	var bodyJSON addAlertJSONType
	json.Unmarshal(bodyBytes, &bodyJSON)

	if bodyJSON.Name == "" || bodyJSON.Expr == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "not all parameters are valid."})
		log.Fatal().Err(errors.New("not all parameters are valid."))
		return
	}

	// rdb := getRedisClient()
	rdb := redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	ctx := context.Background()
	key := "alert:" + bodyJSON.Name
	rdb.Set(ctx, bodyJSON.Name, bodyJSON.Expr, 0)
	rdb.SAdd(ctx, "alertkeys", key)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isSuccessful": true,
		"error":        ""})

	err = rdb.Close()
	if err != nil {
		log.Error().Err(err)
	}
}

func handleAlertDelete(w http.ResponseWriter, r *http.Request) {
	var Id string
	params := r.URL.Query()
	for key, value := range params {
		switch key {
		case "id":
			Id = value[0]
		default:
			log.Error().Err(errors.New("bad parameters for the crypto endpoint."))
		}
	}

	if Id == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "Id parameter is not valid."})
		log.Fatal().Err(errors.New("not all parameters are valid."))
		return
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	ctx := context.Background()

	rdb.Del(ctx, Id)
	setKey := "alert:" + Id
	rdb.SRem(ctx, "alertkeys", setKey)

	json.NewEncoder(w).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Err          string `json:"err"`
	}{IsSuccessful: true, Err: ""})
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		handleAlertPost(w, r)
	} else if r.Method == "DELETE" {
		handleAlertDelete(w, r)
	} else {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

}

func exHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	apiKey := os.Getenv(CHANGELLY_API_KEY_ENV_VAR)
	apiSecret := os.Getenv(CHANGELLY_API_SECRET_ENV_VAR)

	body := struct {
		Jsonrpc string   `json:"jsonrpc"`
		Id      string   `json:"id"`
		Method  string   `json:"method"`
		Params  []string `json:"params"`
	}{
		Jsonrpc: "2.0",
		Id:      "test",
		Method:  "getCurrencies",
		Params:  nil}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		log.Error().Err(err)
	}

	secretBytes := []byte(apiSecret[1 : len(apiSecret)-1])
	mac := hmac.New(sha512.New, secretBytes)
	mac.Write(bodyJSON)

	client := &http.Client{}
	req, err := http.NewRequest("POST", changellyURL, bytes.NewReader(bodyJSON))
	if err != nil {
		log.Error().Err(err)
	}

	macDigest := hex.EncodeToString(mac.Sum(nil))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("api-key", apiKey[1:len(apiKey)-1])
	req.Header.Add("sign", macDigest)

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err)
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	log.Printf(string(responseBody))

	responseUnmarshalled := struct {
		Jsonrpc string   `json:"jsonrpc"`
		Id      string   `json:"id"`
		Result  []string `json:"result"`
	}{}

	err = json.Unmarshal(responseBody, &responseUnmarshalled)
	if err != nil {
		log.Error().Err(err)
	}

	json.NewEncoder(w).Encode(responseUnmarshalled)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	json.NewEncoder(w).Encode(struct {
		IsOK bool   `json:"isOK"`
		Err  string `json:"err"`
	}{IsOK: true, Err: ""})
}

func startServer() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/price", priceHandler)
	http.HandleFunc("/pair", pairHandler)
	http.HandleFunc("/alert", alertHandler)
	http.HandleFunc("/ex", exHandler)

	if err := http.ListenAndServe(":"+*flagPort, nil); err != nil {
		log.Fatal().Err(err)
	}
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func main() {
	setupLogging()
	// go runTgBot()
	go alertManager()
	startServer()
}
