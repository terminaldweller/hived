FROM golang:1.27-alpine3.24 AS builder
COPY go.* /hived/
COPY *.go /hived/
COPY ./vendor/ /hived/vendor/
RUN cd /hived && CGO_ENABLED=0 go build -mod=vendor

FROM alpine:3.24
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
