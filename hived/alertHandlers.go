package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/rs/zerolog/log"
)

func (alertHandler Handler) HandleAlertPost(writer http.ResponseWriter, request *http.Request) {
	var bodyJSON addAlertJSONType

	writer.Header().Add("Content-Type", "application/json")

	err := json.NewDecoder(request.Body).Decode(&bodyJSON)
	if err != nil {
		log.Printf(err.Error())

		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "not all parameters are valid.",
		})
		if err != nil {
			log.Error().Err(err)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}
	}

	if bodyJSON.Name == "" || bodyJSON.Expr == "" {
		err := json.NewEncoder(writer).Encode(map[string]interface{}{
			"isSuccessful": false,
			"error":        "not all parameters are valid.",
		})
		if err != nil {
			log.Error().Err(errFailedUnmarshall)
			http.Error(writer, "internal server error", http.StatusInternalServerError)
		}

		return
	}

	ctx, cancel := context.WithTimeout(request.Context(), redisContextTimeout*time.Second)
	defer cancel()

	key := "alert:" + bodyJSON.Name
	alertHandler.rdb.Set(ctx, bodyJSON.Name, bodyJSON.Expr, 0)
	alertHandler.rdb.SAdd(ctx, "alertkeys", key)

	err = json.NewEncoder(writer).Encode(map[string]interface{}{
		"isSuccessful": true,
		"error":        "",
	})

	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}

func (alertHandler Handler) HandleAlertDelete(writer http.ResponseWriter, request *http.Request) {
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

	alertHandler.rdb.Del(ctx, identifier)
	setKey := "alert:" + identifier
	alertHandler.rdb.SRem(ctx, "alertkeys", setKey)
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

func (alertHandler Handler) HandleAlertGet(writer http.ResponseWriter, request *http.Request) {
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

	redisResult := alertHandler.rdb.Get(ctx, identifier)

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

func (aw appWrapper) alertHandler(echoCtx echo.Context) error {
	writer := echoCtx.Response().Writer
	request := echoCtx.Request()

	addSecureHeaders(&writer)

	handler := Handler{rdb: rdb}

	switch request.Method {
	case http.MethodPost:
		handler.HandleAlertPost(writer, request)
	case http.MethodPut:
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	case http.MethodPatch:
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	case http.MethodDelete:
		handler.HandleAlertDelete(writer, request)
	case http.MethodGet:
		handler.HandleAlertGet(writer, request)
	default:
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}

	return nil
}
