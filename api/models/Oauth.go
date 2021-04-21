package models

type Service_client struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Domain       string `json:"domain"`
}
