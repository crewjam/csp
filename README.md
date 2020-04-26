# csp

[![Build Status](https://travis-ci.org/crewjam/csp.svg?branch=master)](https://travis-ci.org/crewjam/csp)
[![Documentation](https://godoc.org/github.com/crewjam/csp?status.svg)](http://godoc.org/github.com/crewjam/csp)

Package csp provides structures to add Content-Security-Policy headers to HTTP responses.

```go
import (
	"net/http"

	"github.com/crewjam/csp"
)

func HeaderExample(w http.ResponseWriter, r *http.Request) {
	r.Header.Add("Content-Security-Policy", csp.Header{
		DefaultSrc: []string{"'self'", "static.example.com"},
	}.String())
}
```
