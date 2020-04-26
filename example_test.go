package csp_test

import (
	"net/http"

	"github.com/crewjam/csp"
)

func HeaderExample(w http.ResponseWriter, r *http.Request) {
	r.Header.Add("Content-Security-Policy", csp.Header{
		DefaultSrc: []string{"'self'", "static.example.com"},
	}.String())
}
