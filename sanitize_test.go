package main

import (
	"strings"
	"testing"
)

func TestSanitizeUserInput(t *testing.T) {

	type test struct {
		input    string
		want     string
		scenario string
	}

	tests := []test{
		{input: "user", want: "user", scenario: "no change"},
		{input: strings.Repeat("x", 1000), want: strings.Repeat("x", 1000), scenario: "string length not shortened"},
		{input: " user ", want: "user", scenario: "trim white space"},
		{input: "<script>alert('boo')</script>", want: "&lt;script&gt;alert(&#39;boo&#39;)&lt;/script&gt;", scenario: "security"},
		{input: strings.Repeat("x", 1001), want: strings.Repeat("x", 1000), scenario: "string length shortened"},
	}

	s := NewGopherSanitize()
	for _, tc := range tests {
		got := s.SanitizeUserInput(tc.input)
		if tc.want != got {
			t.Fatalf("scenario %s: expected: %v, got: %v", tc.scenario, tc.want, got)
		}
	}
}
