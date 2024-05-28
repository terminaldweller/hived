FROM golang:1.22-alpine3.19 as builder
RUN apk update && apk upgrade
RUN apk add go git
COPY go.* /hived/
RUN cd /hived && go mod download
COPY *.go /hived/
RUN cd /hived && go build

FROM alpine:3.19 as certbuilder
RUN apk add openssl
WORKDIR /certs
RUN openssl req -nodes -new -x509 -subj="/C=US/ST=Denial/L=springfield/O=Dis/CN=localhost" -keyout server.key -out server.cert

# FROM gcr.io/distroless/static-debian10
FROM alpine:3.19
COPY --from=certbuilder /certs /certs
COPY --from=builder /hived/hived /hived/
COPY ./docker-entrypoint.sh /hived/
ENTRYPOINT ["/hived/docker-entrypoint.sh"]
