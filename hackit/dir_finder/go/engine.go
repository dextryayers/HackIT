package main

import (
	"crypto/tls"
	"net/http"
	"time"
)

func CreateClient(timeout int, followRedirects bool) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 90 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if followRedirects {
				return nil
			}
			return http.ErrUseLastResponse
		},
	}
}
