package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func genRandomString() string {
	bytes := make([]byte, 32)

	if _, err := rand.Read(bytes); err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func encrypt(plaintext string) (string, error) {
	cypherText, err := bcrypt.GenerateFromPassword([]byte(plaintext), 10)
	if err != nil {
		return "", err
	}

	return string(cypherText), nil
}

func GenAPIKey() (string, error) {
	apiKey := genRandomString()
	log.Print("Generated APIKEY: ", apiKey)
	encrypted, err := encrypt(apiKey)
	if err != nil {
		return "", err
	}

	return encrypted, nil
}
