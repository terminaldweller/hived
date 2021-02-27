FROM gitpod/workspace-full

RUN apt update && apt upgrade -y
RUN apt install -y go git
COPY go.* /hived/
RUN cd /hived && go mod download
COPY *.go /hived/
RUN cd /hived && go build

COPY ./docker-entrypoint.sh /hived/
ENTRYPOINT ["/hived/docker-entrypoint.sh"]
