FROM alpine:3.13 as builder

RUN apk update && apk upgrade
RUN apk add go git
RUN go get -u github.com/go-telegram-bot-api/telegram-bot-api
COPY *.go /hived/
RUN cd /hived && go build

FROM alpine:3.13
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
