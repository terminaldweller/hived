package main

type PolygonTickerDataLastTrade struct {
	C []int   `json:"c"`
	I string  `json:"i"`
	P float64 `json:"p"`
	S int     `json:"s"`
	T int64   `json:"t"`
	X int     `json:"x"`
}

type PolygonTickerDataDay struct {
	C  float64 `json:"c"`
	H  float64 `json:"h"`
	L  float64 `json:"l"`
	O  float64 `json:"o"`
	V  float64 `json:"v"`
	VW float64 `json:"vw"`
}

type PolygonTickerDataPrevDay struct {
	C  float64 `json:"c"`
	H  float64 `json:"h"`
	L  float64 `json:"l"`
	O  float64 `json:"o"`
	V  float64 `json:"v"`
	VW float64 `json:"vw"`
}

type PolygonTickerDataMin struct {
	C  float64 `json:"c"`
	H  float64 `json:"h"`
	L  float64 `json:"l"`
	N  float64 `json:"n"`
	O  float64 `json:"o"`
	T  float64 `json:"t"`
	V  float64 `json:"v"`
	VW float64 `json:"vw"`
}

type PolygonTickerData struct {
	Min     PolygonTickerDataMin     `json:"min"`
	Day     PolygonTickerDataDay     `json:"day"`
	PrevDay PolygonTickerDataPrevDay `json:"prevDay"`
}

type PolygonTickerResponse struct {
	RequestID        string            `json:"request_id"`
	Status           string            `json:"status"`
	TodaysChange     float64           `json:"todaysChange"`
	TodaysChangePerc float64           `json:"todaysChangePerc"`
	Updated          float64           `json:"updated"`
	Ticker           PolygonTickerData `json:"ticker"`
}
