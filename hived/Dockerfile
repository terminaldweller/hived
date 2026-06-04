FROM golang:1.24-alpine3.22 AS builder
COPY go.* /hived/
COPY *.go /hived/
COPY ./vendor/ /hived/vendor/
RUN cd /hived && CGO_ENABLED=0 go build -mod=vendor

FROM alpine:3.22
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
