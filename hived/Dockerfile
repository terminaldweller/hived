FROM golang:1.22-alpine3.20 as builder
COPY go.* /hived/
RUN cd /hived && go mod download
COPY *.go /hived/
RUN cd /hived && CGO_ENABLED=0 go build

FROM alpine:3.20
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
