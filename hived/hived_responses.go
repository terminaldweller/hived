package main

import "github.com/go-redis/redis/v8"

type AlertHandler struct {
	rdb *redis.Client
}

type HivedPriceResponse struct {
	Name         string  `json:"name"`
	Price        float64 `json:"price"`
	Unit         string  `json:"unit"`
	Err          string  `json:"err"`
	IsSuccessful bool    `json:"isSuccessful"`
}

type HivedPairResponse struct {
	Ratio float64 `json:"ratio"`
}

type HivedAlertGetResponse struct {
	IsSuccessful bool   `json:"isSuccessful"`
	Err          string `json:"err"`
	Key          string `json:"key"`
	Expr         string `json:"expr"`
}

type HivedAlertGenericResponse struct {
	Err          string `json:"err"`
	IsSuccessful bool   `json:"isSuccessful"`
}
