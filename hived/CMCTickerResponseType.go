package main

type CMCTickerStatus struct {
	Timestamp    string `json:"timestamp"`
	ErrorCode    int    `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	Elapsed      int    `json:"elapsed"`
	CreditCount  int    `json:"credit_count"`
	Notice       string `json:"notice"`
}

type CMCTickerQuoteData struct {
	Price                 float64 `json:"price"`
	Volume24H             float64 `json:"volume_24h"`
	VolumeChnage24H       float64 `json:"volume_change_24h"`
	PercentChange1H       float64 `json:"percent_change_1h"`
	PercentChange24h      float64 `json:"percent_change_24h"`
	PercentChange7d       float64 `json:"percent_change_7d"`
	PercentChange30d      float64 `json:"percent_change_30d"`
	MarketCap             float64 `json:"market_cap"`
	MarketCapDominance    float64 `json:"market_cap_dominance"`
	FullyDilutedMarketCap float64 `json:"fully_diluted_market_cap"`
	LastUpdated           string  `json:"last_updated"`
}

type CMCTickerData struct {
	ID                int                           `json:"id"`
	Name              string                        `json:"name"`
	Symbol            string                        `json:"symbol"`
	Slug              string                        `json:"slug"`
	IsActive          int                           `json:"is_active"`
	IsFiat            int                           `json:"is_fiat"`
	CirculatingSupply float64                       `json:"circulating_supply"`
	TotalSupply       float64                       `json:"total_supply"`
	MaxSupply         float64                       `json:"max_supply"`
	DateAdded         string                        `json:"date_added"`
	NumMarketPairs    int                           `json:"num_market_pairs"`
	CMCRank           int                           `json:"cmc_rank"`
	LastUpdated       string                        `json:"last_updated"`
	Quote             map[string]CMCTickerQuoteData `json:"quote"`
}

type CMCTickerResponseType struct {
	Data   map[string]CMCTickerData `json:"data"`
	Status CMCTickerStatus          `json:"status"`
}
