FROM golang:1.24-alpine3.22 AS builder
COPY go.* /hived/
RUN cd /hived && go mod download
COPY *.go /hived/
RUN cd /hived && CGO_ENABLED=0 go build

FROM alpine:3.22
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
