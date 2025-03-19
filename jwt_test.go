package main

import (
	"fmt"
	"testing"
	"time"
)

func TestCreateToken(t *testing.T) {
	secretKey := "mysecretkey"
	claims := GopherJWTClaims{
		"sub":  "1234567890",
		"name": "Fred Smith",
		"iat":  time.Now().Unix(),
		//"exp": time.Now().Add(5 * time.Minute).Unix(), // expiration claim
		"exp": time.Now().Add(time.Hour).Unix(), // expiration claim
	}

	j := NewGopherJWT()
	token, err := j.CreateToken(claims, secretKey)
	if err != nil {
		t.Fatalf("CreateToken returned unexpected error: %v", err)
	}
	fmt.Println("Token: ", token)
}

func TestVerifyTokenAndGetClaims(t *testing.T) {
	secretKey := "mysecretkey"
	claims := GopherJWTClaims{
		"sub":  "1234567890",
		"name": "Fred Smith",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(), // expiration claim
	}

	j := NewGopherJWT()
	token, err := j.CreateToken(claims, secretKey)
	if err != nil {
		t.Fatalf("CreateToken returned unexpected error: %v", err)
	}

	verifiedClaims, err := j.VerifyTokenAndGetClaims(token, secretKey)
	if err != nil {
		t.Fatalf("VerifyTokenAndGetClaims returned unexpected error: %v", err)
	}
	fmt.Println("Verified Claims: ", verifiedClaims)
}

func TestVerifyToken(t *testing.T) {
	secretKey := "mysecretkey"
	claims := GopherJWTClaims{
		"sub":  "1234567890",
		"name": "Fred Smith",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(), // expiration claim
	}

	j := NewGopherJWT()
	token, err := j.CreateToken(claims, secretKey)
	if err != nil {
		t.Fatalf("CreateToken returned unexpected error: %v", err)
	}

	err = j.VerifyToken(token, secretKey)
	if err != nil {
		t.Fatalf("VerifyToken returned unexpected error: %v", err)
	}
	fmt.Println("Token Verified")
}

func TestGetClaims(t *testing.T) {
	secretKey := "mysecretkey"
	claims := GopherJWTClaims{
		"sub":  "1234567890",
		"name": "Fred Smith",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour).Unix(), // expiration claim
	}

	j := NewGopherJWT()
	token, err := j.CreateToken(claims, secretKey)
	if err != nil {
		t.Fatalf("CreateToken returned unexpected error: %v", err)
	}

	actualClaims, err := j.GetClaims(token)
	if err != nil {
		t.Fatalf("GetClaims returned unexpected error: %v", err)
	}
	fmt.Println("Actual Claims: ", actualClaims)
}
