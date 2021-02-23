package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/go-redis/redis/v8"
	"github.com/go-telegram-bot-api/telegram-bot-api"
)

var flagPort = flag.String("port", "8008", "determined the port the sercice runs on")
var flagTgTokenFile = flag.String("tgtoken", "/run/secrets/tg_bot_token", "determines the location of the telegram bot token file")
var changelllyAPIKeyFile = flag.String("chapikey", "/run/secrets/ch_api_key", "determines the file that holds the changelly api key")
var alertFile = flag.String("alertfile", "/run/secrets/alerts", "determines the locaiton of the alert files")
var alertsCheckInterval = flag.Int64("alertinterval", 600., "in seconds, the amount of time between alert checks")
var redisAddress = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
var redisPassword = flag.String("redispassword", "", "determines the password of the redis db")
var redisDB = flag.Int64("redisdb", 0, "determines the db number")

const cryptocomparePriceURL = "https://min-api.cryptocompare.com/data/price?"
const changellyURL = "https://api.changelly.com"
const botChannelID = 146328407

var getRedisClientOnce sync.Once
var getTGBotOnce sync.Once

type TgToken struct {
	Token string `json:"token"`
}

func getTGToken() string {
	tgTokenJsonBytes, err := ioutil.ReadFile(*flagTgTokenFile)
	if err != nil {
		log.Fatal(err)
	}

	var tgToken TgToken

	err = json.Unmarshal(tgTokenJsonBytes, &tgToken)
	if err != nil {
		log.Fatal(err)
	}
	return tgToken.Token
}

func getTgBot() *tgbotapi.BotAPI {
	var tgbot *tgbotapi.BotAPI
	getTGBotOnce.Do(func() {
		tgTokenJsonBytes, err := ioutil.ReadFile(*flagTgTokenFile)
		if err != nil {
			log.Fatal(err)
		}

		var tgToken TgToken

		err = json.Unmarshal(tgTokenJsonBytes, &tgToken)
		if err != nil {
			log.Fatal(err)
		}

		bot, err := tgbotapi.NewBotAPI(tgToken.Token)
		if err != nil {
			log.Panic(err)
		}

		bot.Debug = true
		tgbot = bot
	})
	return tgbot
}

func runTgBot() {
	bot := getTgBot()
	log.Printf("Authorized on account %s", bot.Self.UserName)

	update := tgbotapi.NewUpdate(0)
	update.Timeout = 60

	updates, err := bot.GetUpdatesChan(update)
	if err != nil {
		log.Panic(err)
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

//TODO
func healthHandler(w http.ResponseWriter, r *http.Request) {
}

func cryptoHandler(w http.ResponseWriter, r *http.Request) {
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
			log.Fatal("bad parameters for the crypto endpoint.")
		}
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
			log.Printf(err.err.Error())
		}
	default:
		log.Fatal("this shouldnt have happened")
	}

	var price priceChanStruct
	select {
	case priceCh := <-priceChan:
		price = priceCh
	default:
		log.Fatal("this shouldnt have happened")
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"name": price.name, "price": price.price, "unit": unit})
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
				log.Fatal(err)
			}
		default:
			log.Fatal("bad parameters for the pair endpoint.")
		}
	}
	fmt.Println(one, two, multiplier)

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
				log.Printf(err.err.Error())
			}
		default:
			log.Fatal("this shouldnt have happened")
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
			log.Fatal("this shouldnt have happened")
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
		log.Printf(err.Error())
		return alertsType{}, err
	}
	fmt.Println(val)

	return alertsType{}, nil
}

func alertManager() {
	for {
		alerts, err := getAlerts()
		if err != nil {
			log.Printf(err.Error())
			return
		}
		fmt.Println(alerts)

		for i := range alerts.Alerts {
			expression, err := govaluate.NewEvaluableExpression(alerts.Alerts[i].Expr)
			if err != nil {
				log.Printf(err.Error())
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
					log.Fatal("this shouldnt have happened")
				}
			}

			for i := 0; i < len(vars); i++ {
				select {
				case price := <-priceChan:
					parameters[price.name] = price.price
				default:
					log.Fatal("this shouldnt have happened")
				}
			}

			fmt.Println("parameters:", parameters)
			result, err := expression.Evaluate(parameters)
			if err != nil {
				log.Println(err.Error())
			}

			var resultBool bool
			fmt.Println("result:", result)
			resultBool = result.(bool)
			if resultBool == true {
				bot, err := tgbotapi.NewBotAPI(getTGToken())
				if err != nil {
					log.Panic(err)
				}
				// bot := getTgBot()
				msgText := "notification " + alerts.Alerts[i].Expr + " has been triggered"
				msg := tgbotapi.NewMessage(botChannelID, msgText)
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

func addAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf(err.Error())
	}

	var bodyJSON addAlertJSONType
	json.Unmarshal(bodyBytes, &bodyJSON)
	fmt.Println(bodyJSON)

	// rdb := getRedisClient()
	rdb := redis.NewClient(&redis.Options{
		Addr:         *redisAddress,
		Password:     *redisPassword,
		DB:           int(*redisDB),
		MinIdleConns: 1,
	})
	ctx := context.Background()
	key := "alert:" + bodyJSON.Name
	rdb.Set(ctx, bodyJSON.Name, bodyJSON.Expr, 0)
	rdb.SAdd(ctx, "alertkeys", key)
	json.NewEncoder(w).Encode(map[string]interface{}{"isSuccessful": true, "error": ""})
}

func startServer() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/crypto", cryptoHandler)
	http.HandleFunc("/pair", pairHandler)
	http.HandleFunc("/addalert", addAlertHandler)

	if err := http.ListenAndServe(":"+*flagPort, nil); err != nil {
		log.Fatal(err)
	}
}

func main() {
	go runTgBot()
	go alertManager()
	startServer()
}
