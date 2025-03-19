package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type GopherJWT struct{}

// GopherJWTClaims represent the payload of a JWT
type GopherJWTClaims map[string]interface{}

// GopherJWTHeader represents the header of a JWT
type GopherJWTHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func NewGopherJWT() *GopherJWT {
	return &GopherJWT{}
}

// CreateToken creates a signed JWT with the given claims and secret key.
func (j GopherJWT) CreateToken(claims GopherJWTClaims, secretKey string) (string, error) {
	header := GopherJWTHeader{
		Algorithm: "HS256",
		Type:      "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	claimsBase64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	unsignedToken := headerBase64 + "." + claimsBase64

	signature, err := j.sign(unsignedToken, secretKey)
	if err != nil {
		return "", err
	}

	return unsignedToken + "." + signature, nil
}

// VerifyTokenAndGetClaims verifies a signed JWT and returns the claims if valid.
func (j GopherJWT) VerifyTokenAndGetClaims(token string, secretKey string) (GopherJWTClaims, error) {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	headerBase64 := parts[0]
	claimsBase64 := parts[1]
	signature := parts[2]

	unsignedToken := headerBase64 + "." + claimsBase64

	expectedSignature, err := j.sign(unsignedToken, secretKey)
	if err != nil {
		return nil, err
	}

	if signature != expectedSignature {
		return nil, errors.New("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsBase64)
	if err != nil {
		return nil, err
	}

	var claims GopherJWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	// Check for expiration
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return nil, errors.New("token expired")
		}
	}

	return claims, nil
}

// VerifyToken verifies a signed JWT.
func (j GopherJWT) VerifyToken(token string, secretKey string) error {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("invalid token format")
	}

	headerBase64 := parts[0]
	claimsBase64 := parts[1]
	signature := parts[2]

	unsignedToken := headerBase64 + "." + claimsBase64

	expectedSignature, err := j.sign(unsignedToken, secretKey)
	if err != nil {
		return err
	}

	if signature != expectedSignature {
		return errors.New("invalid signature")
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsBase64)
	if err != nil {
		return err
	}

	var claims GopherJWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return err
	}

	// Check for expiration
	if exp, ok := claims["exp"].(float64); ok {
		if int64(exp) < time.Now().Unix() {
			return errors.New("token expired")
		}
	}

	return nil
}

// GetClaims returns the JWT claims.
func (j GopherJWT) GetClaims(token string) (GopherJWTClaims, error) {

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	//headerBase64 := parts[0]
	claimsBase64 := parts[1]
	//signature := parts[2]

	//unsignedToken := headerBase64 + "." + claimsBase64

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsBase64)
	if err != nil {
		return nil, err
	}

	var claims GopherJWTClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}

func (j GopherJWT) sign(data, secretKey string) (string, error) {

	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return signature, nil
}
