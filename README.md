[![Go Report Card](https://goreportcard.com/badge/github.com/terminaldweller/hived)](https://goreportcard.com/report/github.com/terminaldweller/hived)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1e67ac7026904cddb55ede7097995ad8)](https://www.codacy.com/gh/terminaldweller/hived/dashboard?utm_source=github.com&utm_medium=referral&utm_content=terminaldweller/hived&utm_campaign=Badge_Grade)

# hived

`hived` is a cryptocurrency api server:<br/>

endpoints:

- `/api/crypto/v1/price`: get the price of a cryptocurrency
- `/api/crypto/v1/pair`:
- `/_/`: the pocketbase admin panel
- `/api/crypto/v1/alert`: set a condition to be alerted on when true

You can use arithmatical expressions in the alert endpoint. Hived is using [govaluate](https://github.com/Knetic/govaluate).
Here are some examples:

```txt
bitcoin>ethereum
```

```txt
ethereum*10>(bitcoin+dodge)
```

- `/api/crypto/v1/ticker`: get the latest price of a cryptocurrency

## Options

Hived extends pocketbase so all the pocketbase options are available:

```txt
$ hived -help
PocketBase CLI

Usage:
  hived [command]

Available Commands:
  admin       Manages admin accounts
  migrate     Executes app DB migration scripts
  serve       Starts the web server (default to 127.0.0.1:8090 if no domain is specified)
  update      Automatically updates the current app executable with the latest available version

Flags:
      --automigrate            enable/disable auto migrations (default true)
      --dev                    enable dev mode, aka. printing logs and sql statements to the console
      --dir string             the PocketBase data directory (default "hived/pb_data")
      --encryptionEnv string   the env variable whose value of 32 characters will be used
                               as encryption key for the app settings (default none)
  -h, --help                   help for hived
      --hooksDir string        the directory with the JS app hooks
      --hooksPool int          the total prewarm goja.Runtime instances for the JS app hooks execution (default 25)
      --hooksWatch             auto restart the app on pb_hooks file change (default true)
      --indexFallback          fallback the request to index.html on missing static path (eg. when pretty urls are used with SPA) (default true)
      --migrationsDir string   the directory with the user defined migrations
      --publicDir string       the directory to serve static files (default "hived/pb_public")
      --queryTimeout int       the default SELECT queries timeout in seconds (default 30)
  -v, --version                version for hived

Use "hived [command] --help" for more information about a command.
```

## Supported Sources

## Config File

```toml
keydbAddress = "keydb:6379"
keydbPassword = ""
keydbDB = 0
alertsCheckInterval = 600
tickerCheckInterval = 600
cacheDuration = 600
telegramChannelID = 1234567
telegramBotToken = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ"
```

## Admin Panel

Hived is using [pocketbase](https://github.com/pocketbase/pocketbase). The admin panel provided is available at `/_/`.

## Curl Examples

```bash
# price
curl -u "user:password" -X GET https://hived.mydomain.com/api/crypto/v1/price?name=PEPE&unit=USD

# pair
curl -u "user:password" -X GET https://hived.mydomain.com/api/crypto/v1/pair?one=ETH&two=CAKE&multiplier=4.0

# alert
curl -u "user:password" -X POST -H "Content-Type: application/json" -d '{"name":"alert1", "expr":"ETH>CAKE"}' https://hived.mydomain.com/api/crypto/v1/alert
curl -u "user:password" -X GET -H "Content-Type: application/json" https://hived.mydomain.com/api/crypto/v1/alert?key=alert1
curl -u "user:password" -X DELETE -H "Content-Type: application/json" https://hived.mydomain.com/api/crypto/v1/alert?key=alert1

# ticker
curl -u "user:password" -X POST -H "Content-Type: application/json" -d '{"name":"ethereum"}' https://hived.mydomain.com/api/crypto/v1/ticker
curl -u "user:password" -X GET -H "Content-Type: application/json" https://hived.mydomain.com/api/crypto/v1/ticker?key=ethereum
curl -u "user:password" -X DELETE -H "Content-Type: application/json" https://hived.mydomain.com/api/crypto/v1/ticker?key=ethereum
```

## Deployment

There are a couple of Dockerfiles provided by default in the repo:<br/>

```yaml
services:
  nginx:
    image: nginx:stable
    deploy:
      resources:
        limits:
          memory: 128M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
    ports:
      - "443:443/tcp"
    networks:
      - apinet
    restart: unless-stopped
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - SETGID
      - SETUID
      - NET_BIND_SERVICE
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - /etc/letsencrypt/live/hived.mydomain.com/fullchain.pem:/etc/letsencrypt/live/hived.mydomain.com/fullchain.pem:ro
      - /etc/letsencrypt/live/hived.mydomain.com/privkey.pem:/etc/letsencrypt/live/hived.mydomain.com/privkey.pem:ro
      - pb-vault:/pb/pd-data/
    depends_on:
      - hived
  hived:
    image: hived
    build:
      context: ./hived
      dockerfile: ./Dockerfile_distroless_vendored
    deploy:
      resources:
        limits:
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
    networks:
      - apinet
      - dbnet
    ports:
      - "127.0.0.1:10009:8090"
    entrypoint: ["hived"]
    command: ["serve", "--http=0.0.0.0:8090"]
    depends_on:
      - keydb
    cap_drop:
      - ALL
    environment:
      - SERVER_DEPLOYMENT_TYPE=test
      - HIVED_PRICE_SOURCE=cmc
      - CMC_API_KEY=
      - POLYGON_API_KEY=
      - CRYPTOCOMPARE_API_KEY=
    volumes:
      - ./hived/hived.toml:/hived/hived.toml
    dns:
      - 1.1.1.1
  keydb:
    image: eqalpha/keydb:alpine_x86_64_v6.3.4
    deploy:
      resources:
        limits:
          memory: 256M
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
    networks:
      - dbnet
    ports:
      - "127.0.0.1:6380:6379"
    environment:
      - ALLOW_EMPTY_PASSWORD=yes
    volumes:
      - keydb-data:/data/
networks:
  dbnet:
  apinet:
volumes:
  keydb-data:
  pb-vault:
```
