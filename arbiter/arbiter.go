package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	flagPort      = flag.String("port", "8009", "determines the port the server will listen on")
	flagInterval  = flag.Float64("interval", 10, "In seconds, the delay between checking prices")
	redisDB       = flag.Int64("redisdb", 1, "determines the db number")
	rdb           *redis.Client
	redisAddress  = flag.String("redisaddress", "redis:6379", "determines the address of the redis instance")
	redisPassword = flag.String("redispassword", "", "determines the password of the redis db")
)

const (
	SERVER_DEPLOYMENT_TYPE = "SERVER_DEPLOYMENT_TYPE"
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

func arbHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	if r.Method != "GET" {
		http.Error(w, "Method is not supported.", http.StatusNotFound)
	}
	addSecureHeaders(&w)
	//binance
	//kucoin

}

func startServer(gracefulWait time.Duration) {
	r := mux.NewRouter()
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		// PreferServerCipherSuites: true,
		// CipherSuites: []uint16{
		// 	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		// 	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		// 	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		// 	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		// },
	}
	srv := &http.Server{
		Addr:         "0.0.0.0:" + *flagPort,
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		Handler:      r,
		TLSConfig:    cfg,
	}
	r.HandleFunc("/crypto/arb", arbHandler)

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
	startServer(gracefulWait)
}
