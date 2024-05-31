[![Go Report Card](https://goreportcard.com/badge/github.com/terminaldweller/hived)](https://goreportcard.com/report/github.com/terminaldweller/hived)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/1e67ac7026904cddb55ede7097995ad8)](https://www.codacy.com/gh/terminaldweller/hived/dashboard?utm_source=github.com&utm_medium=referral&utm_content=terminaldweller/hived&utm_campaign=Badge_Grade)

# hived

`hived` is small personal cryptocurrency server:<br/>

- It sends notifications through telegram.<br/>

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

```sh
TELEGRAM_BOT_TOKEN="my-telegram-bot-api-key"
```

If you want to use docker-compose, it's as simple as running `docker-compose up`. You just need to provide the files. You can check the file names in the docker-compose file.<br/>
Both the server itself and the redis image are alpine-based so they're pretty small.<br/>

## telebot
