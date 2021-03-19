package models

type TokenDetails struct {
	AccessToken         string
	RefreshToken        string
	AccessTokenExpires  int64
	RefreshTokenExpires int64
}
