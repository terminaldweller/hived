FROM alpine:3.13 as builder
RUN apk update && apk upgrade
RUN apk add go git
COPY go.* /telebot/
RUN cd /telebot && go mod download
COPY *.go /telebot/
RUN cd /telebot && go build

FROM node:lts-alpine3.13 as certbuilder
RUN apk add openssl
WORKDIR /certs
RUN openssl req -nodes -new -x509 -subj="/C=US/ST=Denial/L=springfield/O=Dis/CN=localhost" -keyout server.key -out server.cert

# FROM gcr.io/distroless/static-debian10
FROM alpine:3.13
COPY --from=certbuilder /certs /certs
COPY --from=builder /telebot/telebot /telebot/
COPY ./docker-entrypoint.sh /telebot/
ENTRYPOINT ["/telebot/docker-entrypoint.sh"]
