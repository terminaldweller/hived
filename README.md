[![Go Report Card](https://goreportcard.com/badge/github.com/terminaldweller/hived)](https://goreportcard.com/report/github.com/terminaldweller/hived)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1e67ac7026904cddb55ede7097995ad8)](https://www.codacy.com/gh/terminaldweller/hived/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=terminaldweller/hived&amp;utm_campaign=Badge_Grade)

# hived
`hived` is the second version of my personal cryptocurrency server:<br/>
* hived is currently using redis as its DB because its tiny and fast.<br/>
* It sends notifications through telegram.<br/>
* telebot and hived talk with grpc.<br/>

Currently it has 5 endpoint:<br/>

### /price
Lets you ask for the price of the currency. You can determine the currency the value is returned in.<br/>

### /pair
Takes in a pair of currencies and a multiplier. Determines and returns the ratio.<br/>

### /alert
#### POST
Takes in a name and a math expression containing the names of the currencies. Checks the expression periodically. Sends a message over telegram when the expression holds true.<br/>
The expression's result must be boolean. As an example:<br/>
```Go
ETH*50>50000.
ETH*60/(DOGE*300000) < 4.
```
You can have as many parameters as you like. The requests for the crypto prices are all turned into individual goroutines so it's fast.<br/>
The expression evaluation is powered by [govaluate](https://github.com/Knetic/govaluate). So for a set of rules and what you can and cannot do please check the documentation over there.<br/>

#### DELETE
Deletes the key from the DB so you will no longer receive updates.<br/>

#### PUT
Updates the alert.<br/.>

#### GET
Fetch the alert with the given name.<br/>

### /ex
Gets the list of currencies that are available to be traded.<br/>

You can check under `./test` for some examples of curl commands.<br/>

### /health
Returns the health status of the service.<br/>

## How to Run
Before you can run this, you need a [telegram bot token](https://core.telegram.org/bots#6-botfather) and a [changelly](https://changelly.com/) API key.<br/>
The keys are put in files and then given to Docker as secrets.The docker entrypoint script then exports these as environment variables.<br/>

```sh
TELEGRAM_BOT_TOKEN="my-telegram-bot-api-key"
```
And
```sh
CHANGELLY_API_KEY:"my-changelly-api-key"
```
And
```sh
CHANGELLY_API_SECRET:"my-changelly-api-secret"
```
If you want to use docker-compose, it's as  simple as running `docker-compose up`. You just need to provide the files. You can check the file names in the docker-compose file.<br/>
Both the server itself and the redis image are alpine-based so they're pretty small.<br/>

## telebot
`telebot` is the service that handles sending notifications through telegram. telebot uses grpc.<br/>
You can find the grpc repo for it [here](https://github.com/terminaldweller/grpc).<br/>

## Gitpod
`hived` is gitpod-ready. Gitpod might need to install some go lsp tools once it is loaded. You will get prompted for those.<br/>

## Docs
You can find the swagger and postman docs under `/api`.<br/>

## TODO
* ~~fix travis~~
* add unit tests
* ~~fix `hived -help` crashing~~
* ~~haproxy~~
* ~~turn the telegram bot into its own microservice~~
* update openapi3.0 spec and postman
* ~~telegram bot's endpoint should be gRPC~~
