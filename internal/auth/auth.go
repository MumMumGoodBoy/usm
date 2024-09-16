package auth

import (
	"net/http"
	"strings"
)

func GetTokenHeader(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", false
	}
	header = strings.TrimPrefix(header, "Bearer ")
	if header == "" {
		return "", false
	}
	return header, true
}
