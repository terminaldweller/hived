package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

func (tickerHandler Handler) HandleTickerGet(writer http.ResponseWriter, request *http.Request) {
	var identifier string

	writer.Header().Add("Content-Type", "application/json")

	params := request.URL.Query()
	for key, value := range params {
		switch key {
		case "key":
			identifier = value[0]
		default:
			log.Error().Err(errUnknownParam)
		}
	}

	if identifier == "" {
		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "Id parameter is not valid.",
		})
		if err != nil {
			log.Error().Err(err)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), redisContextTimeout*time.Second)
	defer cancel()

	redisResult := tickerHandler.rdb.Get(ctx, identifier)

	redisResultString, err := redisResult.Result()
	if err != nil {
		log.Err(err)
	}

	var ErrorString string
	var IsSuccessful bool

	if err == nil {
		ErrorString = ""
		IsSuccessful = true
	} else {
		ErrorString = err.Error()
		IsSuccessful = false
	}

	writer.Header().Add("Content-Type", "application/json")

	err = json.NewEncoder(writer).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Error        string `json:"error"`
		Key          string `json:"key"`
		Expr         string `json:"expr"`
	}{IsSuccessful: IsSuccessful, Error: ErrorString, Key: identifier, Expr: redisResultString})

	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}

func (tickerHandler Handler) HandleTickerDelete(writer http.ResponseWriter, request *http.Request) {
	var identifier string

	writer.Header().Add("Content-Type", "application/json")

	params := request.URL.Query()

	for key, value := range params {
		switch key {
		case "key":
			identifier = value[0]
		default:
			log.Error().Err(errUnknownParam)
		}
	}

	if identifier == "" {
		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "Id parameter is not valid.",
		})
		if err != nil {
			log.Error().Err(err)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), redisContextTimeout*time.Second)
	defer cancel()

	tickerHandler.rdb.Del(ctx, identifier)
	setKey := "ticker:" + identifier
	tickerHandler.rdb.SRem(ctx, "tickerkeys", setKey)
	log.Printf(setKey)

	err := json.NewEncoder(writer).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Err          string `json:"err"`
	}{IsSuccessful: true, Err: ""})
	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}

func (tickerHandler Handler) HandleTickerPost(writer http.ResponseWriter, request *http.Request) {
	var bodyJSON tickerJSONType

	writer.Header().Add("Content-Type", "application/json")

	err := json.NewDecoder(request.Body).Decode(&bodyJSON)
	if err != nil {
		fmt.Println(err.Error())
		log.Printf(err.Error())

		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			// "error":        "not all parameters are valid.",
			"error": "XXX",
		})
		if err != nil {
			log.Error().Err(err)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}
	}

	fmt.Println(bodyJSON.Name)
	if bodyJSON.Name == "" {
		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "name is empty.",
		})
		if err != nil {
			log.Error().Err(errFailedUnmarshall)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), redisContextTimeout*time.Second)
	defer cancel()

	key := "ticker:" + bodyJSON.Name
	tickerHandler.rdb.Set(ctx, bodyJSON.Name, true, 0)
	tickerHandler.rdb.SAdd(ctx, "tickerkeys", key)

	err = json.NewEncoder(writer).Encode(map[string]interface{}{
		"isSuccessful": true,
		"error":        "",
	})

	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}
