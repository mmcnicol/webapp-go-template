package main

import (
	"html"
	"strings"
)

type GopherSanitize struct{}

func NewGopherSanitize() *GopherSanitize {
	return &GopherSanitize{}
}

func (s GopherSanitize) SanitizeUserInput(input string) string {

	sanitized := html.EscapeString(input)
	//sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	//sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.TrimSpace(sanitized)
	maxLength := 1000
	if len(sanitized) > maxLength {
		sanitized = sanitized[:maxLength]
	}
	return sanitized
}
