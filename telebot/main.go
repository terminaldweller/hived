package main

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

var flagPort = flag.String("port", "8000", "determined the port the sercice runs on")

// FIXME-the client should provide the channel ID
var botChannelID = flag.Int64("botchannelid", 146328407, "determines the channel id the telgram bot should send messages to")

const TELEGRAM_BOT_TOKEN_ENV_VAR = "TELEGRAM_BOT_TOKEN"

func getTGBot() *tgbotapi.BotAPI {
	token := os.Getenv(TELEGRAM_BOT_TOKEN_ENV_VAR)
	bot, err := tgbotapi.NewBotAPI(token[1 : len(token)-1])
	if err != nil {
		log.Error().Err(err)
	}
	return bot
}

func sendMessage(bot *tgbotapi.BotAPI, msgText string) error {
	msg := tgbotapi.NewMessage(*botChannelID, msgText)
	bot.Send(msg)
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	var telebotError string
	IsTelebotOk := true

	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(struct {
		IsHivedOk    bool   `json:"isTelebotOK"`
		TelebotError string `json:"telebotError"`
	}{IsHivedOk: IsTelebotOk, TelebotError: telebotError})
}

func msgHandler(w http.ResponseWriter, r *http.Request) {

}

func startServer(gracefulWait time.Duration) {
	r := mux.NewRouter()
	srv := &http.Server{
		Addr:         "0.0.0.0:" + *flagPort,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		Handler:      r,
	}
	r.HandleFunc("/health", healthHandler)
	r.HandleFunc("/msg", msgHandler)

	go func() {
		if err := srv.ListenAndServe(); err != nil {
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
	startServer(gracefulWait)
}
