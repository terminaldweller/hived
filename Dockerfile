FROM alpine:3.13 as builder

RUN apk update && apk upgrade
RUN apk add go git
COPY ./go.* /hived/
RUN cd /hived && go mod download
COPY *.go /hived/
RUN cd /hived && go build

FROM alpine:3.13
COPY --from=builder /hived/hived /hived/
ENTRYPOINT ["/hived/hived"]
