package models

type Service_client struct {
	GrantType string `json:"grant_type" form:"grant_type"`
	Scope     string `json:"scope" form:"scope"`
}
