package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/rs/zerolog/log"
	pb "github.com/terminaldweller/grpc/telebot/v1"
	"google.golang.org/grpc"
)

var (
	flagPort = flag.String("port", "8000", "determined the port the sercice runs on")

	// FIXME-the client should provide the channel ID
	botChannelID = flag.Int64("botchannelid", 146328407, "determines the channel id the telgram bot should send messages to")
)

const (
	TELEGRAM_BOT_TOKEN_ENV_VAR = "TELEGRAM_BOT_TOKEN"
	SERVER_DEPLOYMENT_TYPE     = "SERVER_DEPLOYMENT_TYPE"
)

type server struct {
	pb.UnimplementedNotificationServiceServer
}

func getTGBot() *tgbotapi.BotAPI {
	token := os.Getenv(TELEGRAM_BOT_TOKEN_ENV_VAR)
	bot, err := tgbotapi.NewBotAPI(token[1 : len(token)-1])
	if err != nil {
		log.Error().Err(err)
	}
	return bot
}

func sendMessage(bot *tgbotapi.BotAPI, msgText string, channelID int64) error {
	msg := tgbotapi.NewMessage(channelID, msgText)
	bot.Send(msg)
	return nil
}

func (s *server) Notify(ctx context.Context, NotificationRequest *pb.NotificationRequest) (*pb.NotificationResponse, error) {
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
	flag.Parse()
	port, _ := strconv.Atoi(*flagPort)
	startServer(uint16(port))
}
