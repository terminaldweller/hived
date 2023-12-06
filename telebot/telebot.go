package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/rs/zerolog/log"
	pb "github.com/terminaldweller/grpc/telebot/v1"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc"
)

// FIXME-the client should provide the channel ID.
var botChannelID = flag.Int64(
	"botchannelid",
	146328407, //nolint: gomnd
	"determines the channel id the telgram bot should send messages to")

const (
	telegramBotTokenEnvVar = "TELEGRAM_BOT_TOKEN" //nolint: gosec
	httpClientTimeout      = 5
)

type server struct {
	pb.UnimplementedNotificationServiceServer
}

func GetProxiedClient() (*http.Client, error) {
	var isProxied bool
	proxyURL := os.Getenv("ALL_PROXY")
	if proxyURL == "" {
		proxyURL = os.Getenv("HTTPS_PROXY")
	}

	if proxyURL == "" {
		isProxied = false
	}

	var dialer_proxy proxy.Dialer
	var dialer net.Dialer
	var err error

	if isProxied {
		dialer_proxy, err = proxy.SOCKS5("tcp", proxyURL, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("[GetProxiedClient] : %w", err)
		}
	} else {
		dialer = net.Dialer{
			Timeout: 5 * time.Second,
		}
		if err != nil {
			return nil, fmt.Errorf("[GetProxiedClient] : %w", err)
		}
	}

	dialContext := func(ctx context.Context, network, address string) (net.Conn, error) {
		if isProxied {
			netConn, err := dialer_proxy.Dial(network, address)
			if err == nil {
				return netConn, nil
			}

			return netConn, fmt.Errorf("[dialContext] : %w", err)
		} else {
			netConn, err := dialer.Dial(network, address)
			if err == nil {
				return netConn, nil
			}

			return netConn, fmt.Errorf("[dialContext] : %w", err)
		}
	}

	transport := &http.Transport{
		DialContext:       dialContext,
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport:     transport,
		Timeout:       httpClientTimeout * time.Second,
		CheckRedirect: nil,
		Jar:           nil,
	}

	return client, nil
}

func getTGBot() *tgbotapi.BotAPI {
	token := os.Getenv(telegramBotTokenEnvVar)

	// client, err := GetProxiedClient()
	// if err != nil {
	// 	log.Fatal().Err(err)
	// }

	// bot, err := tgbotapi.NewBotAPIWithClient(token[1:len(token)-1], client)
	bot, err := tgbotapi.NewBotAPI(token[1 : len(token)-1])
	if err != nil {
		log.Fatal().Err(err)
	}

	return bot
}

func sendMessage(bot *tgbotapi.BotAPI, msgText string, channelID int64) error {
	msg := tgbotapi.NewMessage(channelID, msgText)
	_, err := bot.Send(msg)

	return err
}

func (s *server) Notify(
	ctx context.Context,
	NotificationRequest *pb.NotificationRequest,
) (*pb.NotificationResponse, error) {
	var err error

	tgbotapi := getTGBot()

	if NotificationRequest.ChannelId == 0 {
		err = sendMessage(tgbotapi, NotificationRequest.NotificationText, *botChannelID)
	} else {
		err = sendMessage(tgbotapi, NotificationRequest.NotificationText, NotificationRequest.ChannelId)
	}

	if err != nil {
		return &pb.NotificationResponse{Error: err.Error(), IsOK: false}, err
	}

	return &pb.NotificationResponse{Error: "", IsOK: true}, nil
}

func startServer(port uint16) {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		log.Fatal().Err(err)
	}

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	pb.RegisterNotificationServiceServer(grpcServer, &server{})

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatal().Err(err)
	}
}

func main() {
	flagPort := flag.String("port", "8000", "determines the port the service runs on")
	flag.Parse()

	port, _ := strconv.Atoi(*flagPort)

	startServer(uint16(port))
}
