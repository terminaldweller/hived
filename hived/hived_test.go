package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-redis/redis/v8"
)

const (
	endpoint = "https://api.terminaldweller.com/crypto/v1"
)

var (
	redisAddress  = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword = flag.String("redispassword", "", "determines the password of the redis db")
	redisDB       = flag.Int64("redisdb", 0, "determines the db number")
)

func errorHandler(recorder *httptest.ResponseRecorder, t *testing.T, err error) {
	if err != nil {
		t.Errorf(err.Error())
	}

	if recorder.Code != 200 {
		t.Errorf("returned code: %d", recorder.Code)
	}
}

func TestPriceHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, endpoint+"/price?name=BTC&unit=USD", nil)
	recorder := httptest.NewRecorder()
	PriceHandler(recorder, req)
	errorHandler(recorder, t, err)

	var hivedPriceResponse HivedPriceResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedPriceResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedPriceResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}

func TestPairHandler(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, endpoint+"/pair?one=ETH&two=CAKE&multiplier=4.0", nil)
	recorder := httptest.NewRecorder()
	PairHandler(recorder, req)
	errorHandler(recorder, t, err)

	var hivedPairResponse HivedPairResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedPairResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}
}

func TestAlertHandlerPhase1(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	postValues := map[string]string{"name": "alertTest", "expr": "ETH < 10000"}

	postData, err := json.Marshal(postValues)
	if err != nil {
		fmt.Println(err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, endpoint+"/alert", bytes.NewBuffer(postData))

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertPost(recorder, req)
	errorHandler(recorder, t, err)

	var hivedAlertGenericResponse HivedAlertGenericResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedAlertGenericResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedAlertGenericResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}

func TestAlertHandlerPhase2(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	req, err := http.NewRequest(http.MethodGet, endpoint+"/alert?key=alertTest", nil)
	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertGet(recorder, req)
	errorHandler(recorder, t, err)

	var hivedAlertGetResponse HivedAlertGetResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedAlertGetResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedAlertGetResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}

func TestAlertHandlerPhase3(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	postValues := map[string]string{"name": "alertTest", "expr": "ETH > 10000"}

	postData, err := json.Marshal(postValues)
	if err != nil {
		fmt.Println(err.Error())
	}

	req, err := http.NewRequest(http.MethodPut, endpoint+"/alert", bytes.NewBuffer(postData))

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertGet(recorder, req)
	errorHandler(recorder, t, err)
}

func TestAlertHandlerPhase4(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	req, err := http.NewRequest(http.MethodGet, endpoint+"/alert?key=alertTest", nil)
	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertGet(recorder, req)
	errorHandler(recorder, t, err)

	var hivedAlertGetResponse HivedAlertGetResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedAlertGetResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedAlertGetResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}

func TestAlertHandlerPhase5(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	req, err := http.NewRequest(http.MethodDelete, endpoint+"/alert?key=alertTest", nil)
	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertGet(recorder, req)
	errorHandler(recorder, t, err)

	var hivedAlertGenericResponse HivedAlertGenericResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedAlertGenericResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedAlertGenericResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}

func TestAlertHandlerPhase6(t *testing.T) {
	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	req, err := http.NewRequest(http.MethodGet, endpoint+"/alert?key=alertTest", nil)

	recorder := httptest.NewRecorder()
	alertHandler := AlertHandler{rdb: rdb}
	alertHandler.HandleAlertGet(recorder, req)
	errorHandler(recorder, t, err)

	var hivedAlertGetResponse HivedAlertGetResponse

	bodyBytes, err := ioutil.ReadAll(recorder.Body)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	err = json.Unmarshal(bodyBytes, &hivedAlertGetResponse)
	if err != nil {
		errorHandler(recorder, t, err)
	}

	if !hivedAlertGetResponse.IsSuccessful {
		fmt.Println(err.Error())
		errorHandler(recorder, t, err)
	}
}
