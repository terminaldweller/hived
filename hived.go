package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/go-telegram-bot-api/telegram-bot-api"
)

var flagPort = flag.String("port", "8008", "determined the port the sercice runs on")
var flagTgTokenFile = flag.String("tgtoken", "/run/secrets/tg_bot_token", "determines the location of the telegram bot token file")
var changelllyAPIKeyFile = flag.String("chapikey", "/run/secrets/ch_api_key", "determines the file that holds the changelly api key")
var alertFile = flag.String("alertfile", "/run/secrets/alerts", "determines the locaiton of the alert files")
var alertsCheckInterval = flag.Int64("alertinterval", 60., "in seconds, the amount of time between alert checks")

const cryptocomparePriceURL = "https://min-api.cryptocompare.com/data/price?"
const changellyURL = "https://api.changelly.com"

func getTgToken() string {
	tgTokenJsonBytes, err := ioutil.ReadFile(*flagTgTokenFile)
	if err != nil {
		log.Fatal(err)
	}

	type TgToken struct {
		Token string `json:"token"`
	}

	var tgToken TgToken

	err = json.Unmarshal(tgTokenJsonBytes, &tgToken)
	if err != nil {
		log.Fatal(err)
	}

	return tgToken.Token
}

func runTgBot() {
	botToken := getTgToken()
	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = true

	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)
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

	//FIXME-blocks forever
	priceChan <- priceChanStruct{name: name, price: jsonBody[unit]}
	errChan <- errorChanStruct{hasError: false, err: nil}
	fmt.Println("done and done")
}

//TODO
func healthHandler(w http.ResponseWriter, r *http.Request) {
}

func cryptoHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/crypto" {
		http.Error(w, "404 not found.", http.StatusNotFound)
		return
	}

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
	fmt.Println("getting fucked here")

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

func getAlerts() map[string]interface{} {
	alertsBytes, err := ioutil.ReadFile(*flagTgTokenFile)
	if err != nil {
		log.Fatal(err)
		return make(map[string]interface{})
	}

	alertsJson := make(map[string]interface{})

	err = json.Unmarshal(alertsBytes, &alertsJson)
	if err != nil {
		log.Fatal(err)
		return make(map[string]interface{})
	}

	return alertsJson
}

func alertManager() {
	alerts := getAlerts()
	fmt.Println(alerts)
}

func startServer() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/crypto", cryptoHandler)
	http.HandleFunc("/pair", pairHandler)

	if err := http.ListenAndServe(":"+*flagPort, nil); err != nil {
		log.Fatal(err)
	}
}

func main() {
	go runTgBot()
	go alertManager()
	startServer()
}
