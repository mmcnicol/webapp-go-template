package main

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

type GopherCSRF struct{}

func NewGopherCSRF() *GopherCSRF {
	return &GopherCSRF{}
}

func (c GopherCSRF) GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	token := base64.StdEncoding.EncodeToString(b)
	return token, nil
}

func (c GopherCSRF) SetCSRFCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
	})
}

func (c GopherCSRF) GetCSRFCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}
