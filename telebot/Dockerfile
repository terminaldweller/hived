FROM alpine:3.13 as builder
RUN apk update && apk upgrade
RUN apk add go git
COPY go.* /telebot/
RUN cd /telebot && go mod download
COPY *.go /telebot/
RUN cd /telebot && go build

FROM gcr.io/distroless/static-debian10
COPY --from=builder /telebot/telebot /telebot/
COPY ./docker-entrypoint.sh /telebot/
ENTRYPOINT ["/telebot/docker-entrypoint.sh"]
