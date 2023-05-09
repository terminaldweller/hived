package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	cryptocomparePriceURL        = "https://min-api.cryptocompare.com/data/price?"
	telegramBotTokenEnvVar       = "TELEGRAM_BOT_TOKEN" //nolint: gosec
	serverDeploymentType         = "SERVER_DEPLOYMENT_TYPE"
	httpClientTimeout            = 5
	getTimeout                   = 5
	serverTLSReadTimeout         = 15
	serverTLSWriteTimeout        = 15
	defaultGracefulShutdown      = 15
	redisContextTimeout          = 2
	pingTimeout                  = 5
	alertCheckIntervalDefault    = 600
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

func GetProxiedClient() (*http.Client, error) {
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

	return client, nil
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

func sendToTg(address, msg string, channelID int64) {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatal().Err(err)
	}
	defer conn.Close()

	c := pb.NewNotificationServiceClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), telegramTimeout*time.Second)
	defer cancel()

	response, err := c.Notify(
		ctx,
		&pb.NotificationRequest{
			NotificationText: msg,
			ChannelId:        channelID,
			RequestTime:      timestamppb.Now(),
		})
	if err != nil {
		log.Error().Err(err)
	}

	log.Info().Msg(fmt.Sprintf("%v", response))
}

type priceChanStruct struct {
	name  string
	price float64
}

type errorChanStruct struct {
	hasError bool
	err      error
}

// type APISource int

const (
	CryptoCompareSource = iota
	// CoinGeckoSource
	// CoinCapSource
)

// TODO-add more sources.
// TODO-do a round robin.
func chooseGetPriceSource() int {
	return CryptoCompareSource
}

func getPrice(ctx context.Context,
	name, unit string,
	waitGroup *sync.WaitGroup,
	priceChan chan<- priceChanStruct,
	errChan chan<- errorChanStruct,
) {
	val, err := rdb.Get(ctx, name+"_price").Float64()

	if err != nil {
		source := chooseGetPriceSource()

		if source == CryptoCompareSource {
			getPriceFromCryptoCompare(ctx, name, unit, waitGroup, priceChan, errChan)
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

	log.Error().Err(err)
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

	client, err := GetProxiedClient()
	if err != nil {
		getPriceFromCryptoCompareErrorHandler(err, name, priceChan, errChan)

		return
	}

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

func PriceHandler(writer http.ResponseWriter, request *http.Request) {
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

		return
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
	}
}

func PairHandler(w http.ResponseWriter, r *http.Request) {
	var err error

	w.Header().Add("Content-Type", "application/json")

	if r.Method != http.MethodGet {
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
			log.Fatal().Err(errUnknownParam)
		}
	}

	if one == "" || two == "" || multiplier == 0. {
		log.Error().Err(errIncompParams)
	}

	var waitGroup sync.WaitGroup

	priceChan := make(chan priceChanStruct, 2) //nolint: gomnd
	errChan := make(chan errorChanStruct, 2)   //nolint: gomnd

	defer close(priceChan)
	defer close(errChan)

	ctx, cancel := context.WithTimeout(r.Context(), getTimeout*time.Second)
	defer cancel()

	waitGroup.Add(2) //nolint: gomnd

	go getPrice(ctx, one, "USD", &waitGroup, priceChan, errChan)
	go getPrice(ctx, two, "USD", &waitGroup, priceChan, errChan)

	waitGroup.Wait()

	for i := 0; i < 2; i++ {
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
			log.Error().Err(errBadLogic)
		}
	}

	ratio := priceOne * multiplier / priceTwo

	log.Info().Msg(fmt.Sprintf("%v", ratio))

	err = json.NewEncoder(w).Encode(map[string]interface{}{"ratio": ratio})
	if err != nil {
		log.Error().Err(err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

type alertType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

type alertsType struct {
	Alerts []alertType `json:"alerts"`
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

func alertManagerWorker(alert alertType) {
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

	for i := 0; i < len(vars); i++ {
		select {
		case err := <-errChan:
			if err.hasError {
				log.Printf(err.err.Error())
			}
		default:
			log.Error().Err(errBadLogic)
		}
	}

	for i := 0; i < len(vars); i++ {
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

	token := os.Getenv(telegramBotTokenEnvVar)
	msgText := "notification " + alert.Expr + " has been triggered"

	tokenInt, err := strconv.ParseInt(token[1:len(token)-1], 10, 64)

	if err == nil {
		log.Error().Err(err)
	}

	sendToTg("telebot:8000", msgText, tokenInt)
}

func alertManager(alertsCheckInterval int64) {
	for {
		alerts := getAlerts()

		log.Info().Msg(fmt.Sprintf("%v", alerts))

		for alertIndex := range alerts.Alerts {
			go alertManagerWorker(alerts.Alerts[alertIndex])
		}

		time.Sleep(time.Second * time.Duration(alertsCheckInterval))
	}
}

type addAlertJSONType struct {
	Name string `json:"name"`
	Expr string `json:"expr"`
}

func (alertHandler AlertHandler) HandleAlertPost(writer http.ResponseWriter, request *http.Request) {
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

func (alertHandler AlertHandler) HandleAlertDelete(writer http.ResponseWriter, request *http.Request) {
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

func (alertHandler AlertHandler) HandleAlertGet(writer http.ResponseWriter, request *http.Request) {
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
	if err == nil {
		ErrorString = ""
	} else {
		ErrorString = err.Error()
	}

	writer.Header().Add("Content-Type", "application/json")

	err = json.NewEncoder(writer).Encode(struct {
		IsSuccessful bool   `json:"isSuccessful"`
		Error        string `json:"error"`
		Key          string `json:"key"`
		Expr         string `json:"expr"`
	}{IsSuccessful: true, Error: ErrorString, Key: identifier, Expr: redisResultString})

	if err != nil {
		log.Error().Err(err)
		http.Error(writer, "internal server error", http.StatusInternalServerError)
	}
}

func alertHandler(writer http.ResponseWriter, request *http.Request) {
	addSecureHeaders(&writer)

	alertHandler := AlertHandler{rdb: rdb}

	switch request.Method {
	case http.MethodPost:
		alertHandler.HandleAlertPost(writer, request)
	case http.MethodPut:
		alertHandler.HandleAlertPost(writer, request)
	case http.MethodPatch:
		alertHandler.HandleAlertPost(writer, request)
	case http.MethodDelete:
		alertHandler.HandleAlertDelete(writer, request)
	case http.MethodGet:
		alertHandler.HandleAlertGet(writer, request)
	default:
		http.Error(writer, "Method is not supported.", http.StatusNotFound)
	}
}

func healthHandler(writer http.ResponseWriter, request *http.Request) {
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
	}
}

func robotsHandler(writer http.ResponseWriter, r *http.Request) {
	writer.Header().Add("Content-Type", "text/plain")
	addSecureHeaders(&writer)

	_, err := writer.Write([]byte("User-Agents: *\nDisallow: /\n"))
	if err != nil {
		log.Error().Err(err)
	}

	http.Error(writer, "internal server error", http.StatusInternalServerError)
}

func startServer(gracefulWait time.Duration, flagPort string) {
	router := mux.NewRouter()

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		PreferServerCipherSuites: true,
	}

	srv := &http.Server{
		Addr:         "0.0.0.0:" + flagPort,
		WriteTimeout: time.Second * serverTLSWriteTimeout,
		ReadTimeout:  time.Second * serverTLSReadTimeout,
		Handler:      router,
		TLSConfig:    cfg,
	}

	router.HandleFunc("/crypto/v1/health", healthHandler)
	router.HandleFunc("/crypto/v1/price", PriceHandler)
	router.HandleFunc("/crypto/v1/pair", PairHandler)
	router.HandleFunc("/crypto/v1/alert", alertHandler)
	router.HandleFunc("/crypto/v1/robots.txt", robotsHandler)

	go func() {
		var certPath, keyPath string

		switch os.Getenv(serverDeploymentType) {
		case "deployment":
			certPath = "/etc/letsencrypt/live/api.terminaldweller.com/fullchain.pem"
			keyPath = "/etc/letsencrypt/live/api.terminaldweller.com/privkey.pem"
		case "test":
			certPath = "/certs/server.cert"
			keyPath = "/certs/server.key"
		default:
			log.Fatal().Err(errUnknownDeploymentKind)
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

	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err)
	} else {
		log.Info().Msg("gracefully shut down the server")
	}
}

func setupLogging() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
}

func main() {
	var gracefulWait time.Duration

	flagPort := flag.String("port", "8008", "determined the port the sercice runs on")
	redisAddress := flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword := flag.String("redispassword", "", "determines the password of the redis db")
	redisDB := flag.Int64("redisdb", 0, "determines the db number")
	alertsCheckInterval := flag.Int64(
		"alertinterval",
		alertCheckIntervalDefault,
		"in seconds, the amount of time between alert checks")

	flag.DurationVar(
		&gracefulWait, "gracefulwait",
		time.Second*defaultGracefulShutdown,
		"the duration to wait during the graceful shutdown")

	flag.Parse()

	rdb = redis.NewClient(&redis.Options{
		Addr:     *redisAddress,
		Password: *redisPassword,
		DB:       int(*redisDB),
	})
	defer rdb.Close()

	setupLogging()

	go alertManager(*alertsCheckInterval)

	startServer(gracefulWait, *flagPort)
}
