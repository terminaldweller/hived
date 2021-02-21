package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/go-telegram-bot-api/telegram-bot-api"
)

var flagPort = flag.String("port", "8008", "determined the port the sercice runs on")
var flagTgTokenFile = flag.String("tgtokenfile", "/run/secrets/tg_bot_token", "determines the location of the telegram bot token file")

const cryptocomparePriceURL = "https://min-api.cryptocompare.com/data/price?"

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

func sendGetToCryptoCompare(ccurl, name, unit string) (float64, string, error) {
	params := "fsym=" + url.QueryEscape(name) + "&" +
		"tsyms=" + url.QueryEscape(unit)
	path := ccurl + params
	fmt.Println(path)
	resp, err := http.Get(path)
	if err != nil {
		log.Fatal(err)
		return 0., "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
		return 0., "", err
	}

	jsonBody := make(map[string]float64)
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		log.Fatal(err)
		return 0., "", err
	}

	fmt.Println(string(body))

	return jsonBody[unit], unit, nil
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
		}
	}

	price, unit, err := sendGetToCryptoCompare(cryptocomparePriceURL, name, unit)
	if err != nil {
		log.Fatal(err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"name": price, "unit": unit})
}

func startServer() {
	http.HandleFunc("/crypto", cryptoHandler)
	http.HandleFunc("/health", healthHandler)

	if err := http.ListenAndServe(":"+*flagPort, nil); err != nil {
		log.Fatal(err)
	}
}

func main() {
	go runTgBot()
	startServer()
}
