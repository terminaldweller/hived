FROM alpine:3.13 as builder
ENV GOPROXY=https://goproxy.io
RUN apk update && apk upgrade
RUN apk add go git
ENV GOPROXY=https://goproxy.io
COPY go.* /arbiter/
RUN cd /arbiter && go mod download
COPY *.go /arbiter/
RUN cd /arbiter && go build

FROM alpine:3.15 as certbuilder
RUN apk add openssl
WORKDIR /certs
RUN openssl req -nodes -new -x509 -subj="/C=US/ST=Denial/L=springfield/O=Dis/CN=localhost" -keyout server.key -out server.cert

# FROM gcr.io/distroless/static-debian10
FROM alpine:3.13
COPY --from=certbuilder /certs /certs
COPY --from=builder /arbiter/arbiter /arbiter/
ENTRYPOINT ["/arbiter/arbiter"]
