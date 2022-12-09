package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	pb "github.com/terminaldweller/grpc/telebot/v1"
	"google.golang.org/grpc"
)

var (
	flagPort            = flag.String("port", "8008", "determined the port the sercice runs on")
	alertsCheckInterval = flag.Int64("alertinterval", 600., "in seconds, the amount of time between alert checks")
	redisAddress        = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword       = flag.String("redispassword", "", "determines the password of the redis db")
	redisDB             = flag.Int64("redisdb", 0, "determines the db number")
	botChannelID        = flag.Int64("botchannelid", 146328407, "determines the channel id the telgram bot should send messages to")
	cacheDuration       = flag.Float64("cacheDuration", 300_000, "determines the price cache validity duration in miliseconds")
	rdb                 *redis.Client
)

const (
	cryptocomparePriceURL        = "https://min-api.cryptocompare.com/data/price?"
	coingeckoAPIURLv3            = "https://api.coingecko.com/api/v3"
	changellyURL                 = "https://api.changelly.com"
	TELEGRAM_BOT_TOKEN_ENV_VAR   = "TELEGRAM_BOT_TOKEN"
	CHANGELLY_API_KEY_ENV_VAR    = "CHANGELLY_API_KEY"
	CHANGELLY_API_SECRET_ENV_VAR = "CHANGELLY_API_SECRET"
	SERVER_DEPLOYMENT_TYPE       = "SERVER_DEPLOYMENT_TYPE"
)

// OWASP: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
func addSecureHeaders(w *http.ResponseWriter) {
	(*w).Header().Set("Cache-Control", "no-store")
	(*w).Header().Set("Content-Security-Policy", "default-src https;")
	(*w).Header().Set("Strict-Transport-Security", "max-age=63072000;")
	(*w).Header().Set("X-Content-Type-Options", "nosniff")
	(*w).Header().Set("X-Frame-Options", "DENY")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
}

func sendToTg(address, msg string, channelId int64) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer conn.Close()

	c := pb.NewNotificationServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	r, err := c.Notify(ctx, &pb.NotificationRequest{NotificationText: msg, ChannelId: channelId})
	if err != nil {
		log.Fatal().Err(err)
	}

	log.Info().Msg(fmt.Sprintf("%v", r))
}

type priceChanStruct struct {
	name  string
	price float64
}

type errorChanStruct struct {
	hasError bool
	err      error
}

type APISource int

const (
	CryptoCompareSource = iota
	CoinGeckoSource
	CoinCapSource
)

// TODO-add more sources
// TODO-do a round robin
func chooseGetPriceSource() int {
	return CryptoCompareSource
}

func getPrice(name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {

	// check price cache
	ctx := context.Background()
	val, err := rdb.Get(ctx, name+"_price").Float64()
	if err != nil {
		fmt.Println("price cache miss")
		source := chooseGetPriceSource()

		if source == CryptoCompareSource {
			getPriceFromCryptoCompare(name, unit, wg, priceChan, errChan)
		}
	} else {
		fmt.Println("price cache hit ", val)
		priceChan <- priceChanStruct{name: name, price: val}
		errChan <- errorChanStruct{hasError: false, err: nil}
		wg.Done()
	}
}

func getPriceFromCryptoCompare(
	name, unit string,
	wg *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct) {
	defer wg.Done()

	params := "fsym=" + url.QueryEscape(name) + "&" +
		"tsyms=" + url.QueryEscape(unit)
	path := cryptocomparePriceURL + params
	resp, err := http.Get(path)
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

	jsonBody := make(map[string]float64)
	err = json.Unmarshal(body, &jsonBody)
	if err != nil {
		priceChan <- priceChanStruct{name: name, price: 0.}
		errChan <- errorChanStruct{hasError: true, err: err}
		log.Error().Err(err)
	}

	log.Info().Msg(string(body))

	// add a price cache
	ctx := context.Background()
	err = rdb.Set(ctx, name+"_price", jsonBody[unit], time.Duration(*cacheDuration*1000000)).Err()
	if err != nil {
		log.Error().Err(err)
	}

	priceChan <- priceChanStruct{name: name, price: jsonBody[unit]}
	errChan <- errorChanStruct{hasError: false, err: nil}
}

func PriceHandler(w http.ResponseWriter, r *http.Request) {
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
	// TODO- check cache
	go getPrice(name, unit, &wg, priceChan, errChan)
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

func PairHandler(w http.ResponseWriter, r *http.Request) {
	var err error
	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}
	addSecureHeaders(&w)

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
	go getPrice(one, "USD", &wg, priceChan, errChan)
	go getPrice(two, "USD", &wg, priceChan, errChan)
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
	log.Info().Msg(fmt.Sprintf("%v", ratio))
	json.NewEncoder(w).Encode(map[string]interface{}{"ratio": ratio})
}

type alertType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

type alertsType struct {
	Alerts []alertType `json:"alerts"`
}

func getAlerts() (alertsType, error) {
	var alerts alertsType
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

func alertManager() {
	for {
		alerts, err := getAlerts()
		if err != nil {
			log.Error().Err(err)
			return
		}
		log.Info().Msg(fmt.Sprintf("%v", alerts))

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
				// TODO-get from cache
				go getPrice(vars[i], "USD", &wg, priceChan, errChan)
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

			log.Info().Msg(fmt.Sprintf("parameters: %v", parameters))
			result, err := expression.Evaluate(parameters)
			if err != nil {
				log.Error().Err(err)
			}

			var resultBool bool
			log.Info().Msg(fmt.Sprintf("result: %v", result))
			resultBool = result.(bool)
			if resultBool == true {
				token := os.Getenv(TELEGRAM_BOT_TOKEN_ENV_VAR)
				msgText := "notification " + alerts.Alerts[i].Expr + " has been triggered"
				tokenInt, err := strconv.ParseInt(token[1:len(token)-1], 10, 64)
				if err != nil {
					log.Fatal().Err(err)
				}
				sendToTg("telebot:8000", msgText, tokenInt)
			}
		}

		time.Sleep(time.Second * time.Duration(*alertsCheckInterval))
	}
}

type addAlertJSONType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

func (this AlertHandler) HandleAlertPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
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

	ctx := context.Background()
	key := "alert:" + bodyJSON.Name
	this.rdb.Set(ctx, bodyJSON.Name, bodyJSON.Expr, 0)
	this.rdb.SAdd(ctx, "alertkeys", key)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"isSuccessful": true,
		"error":        ""})
}

func (this AlertHandler) HandleAlertDelete(w http.ResponseWriter, r *http.Request) {
	var Id string
	w.Header().Add("Content-Type", "application/json")
	params := r.URL.Query()
	for key, value := range params {
		switch key {
		case "key":
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

	ctx := context.Background()

	this.rdb.Del(ctx, Id)
	setKey := "alert:" + Id
	this.rdb.SRem(ctx, "alertkeys", setKey)
	log.Printf(setKey)

	json.NewEncoder(w).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Err          string `json:"err"`
	}{IsSuccessful: true, Err: ""})
}

func (this AlertHandler) HandleAlertGet(w http.ResponseWriter, r *http.Request) {
	var Id string
	w.Header().Add("Content-Type", "application/json")
	params := r.URL.Query()
	for key, value := range params {
		switch key {
		case "key":
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

	ctx := context.Background()

	redisResult := this.rdb.Get(ctx, Id)
	redisResultString, err := redisResult.Result()
	if err != nil {
		log.Err(err)
	}

	var ErrorString string
	if err == nil {
		ErrorString = ""
	} else {
		ErrorString = err.Error()
	}

	w.Header().Add("Content-Type", "application/json")

	json.NewEncoder(w).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Error        string `json:"error"`
		Key          string `json:"key"`
		Expr         string `json:"expr"`
	}{IsSuccessful: true, Error: ErrorString, Key: Id, Expr: redisResultString})
}

func alertHandler(w http.ResponseWriter, r *http.Request) {
	addSecureHeaders(&w)
	alertHandler := AlertHandler{rdb: rdb}
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		alertHandler.HandleAlertPost(w, r)
	} else if r.Method == "DELETE" {
		alertHandler.HandleAlertDelete(w, r)
	} else if r.Method == "GET" {
		alertHandler.HandleAlertGet(w, r)
	} else {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}
}

func exHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	addSecureHeaders(&w)
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
	var RedisError string
	var HivedError string
	IsHivedOk := true
	var IsRedisOk bool

	addSecureHeaders(&w)
	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}

	pingCtx := context.Background()
	pingResponse := rdb.Ping(pingCtx)
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

	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(struct {
		IsHivedOk  bool   `json:"isHivedOk"`
		HivedError string `json:"hivedError"`
		IsRedisOk  bool   `json:"isRedisOk"`
		RedisError string `json:"redisError"`
	}{IsHivedOk: IsHivedOk, HivedError: HivedError, IsRedisOk: IsRedisOk, RedisError: RedisError})
}

func robotsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "text/plain")
	addSecureHeaders(&w)
	json.NewEncoder(w).Encode(struct {
		UserAgents string `json:"User-Agents"`
		Disallow   string `json:"Disallow"`
	}{"*", "/"})
}

func startServer(gracefulWait time.Duration) {
	r := mux.NewRouter()
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         "0.0.0.0:" + *flagPort,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		Handler:      r,
		TLSConfig:    cfg,
	}
	r.HandleFunc("/crypto/v1/health", healthHandler)
	r.HandleFunc("/crypto/v1/price", PriceHandler)
	r.HandleFunc("/crypto/v1/pair", PairHandler)
	r.HandleFunc("/crypto/v1/alert", alertHandler)
	r.HandleFunc("/crypto/v1/ex", exHandler)
	r.HandleFunc("/crypto/v1/robots.txt", robotsHandler)

	go func() {
		var certPath, keyPath string
		if os.Getenv(SERVER_DEPLOYMENT_TYPE) == "deployment" {
			certPath = "/certs/fullchain1.pem"
			keyPath = "/certs/privkey1.pem"
		} else if os.Getenv(SERVER_DEPLOYMENT_TYPE) == "test" {
			certPath = "/certs/server.cert"
			keyPath = "/certs/server.key"
		} else {
			log.Fatal().Err(errors.New(fmt.Sprintf("unknown deployment kind: %s", SERVER_DEPLOYMENT_TYPE)))
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

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
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
	go alertManager()
	startServer(gracefulWait)
}
