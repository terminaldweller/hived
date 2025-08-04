FROM debian:bookworm-slim AS builder
RUN apt-get update && \
      apt-get install -y curl bash perl6-readline && \
      curl https://raw.githubusercontent.com/a16z/helios/master/heliosup/install | bash && \
      root/.helios/bin/heliosup install

FROM debian:bookworm-slim
RUN apt-get update && \
      apt-get install -y libc6
ENV HOME=/home/helios
RUN set -eux; \
  adduser -u 1001 --home $HOME helios
COPY --from=builder /root/.helios/bin/helios /usr/local/bin/helios
COPY --from=builder /root/.helios/bin/heliosup /usr/local/bin/heliosup
RUN chown -R helios:helios "$HOME"
