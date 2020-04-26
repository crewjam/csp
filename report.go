package csp

// Report represents a CSP violation report
//
// ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only
type Report struct {
	BlockedURI         string `json:"blocked-uri"`         // The URI of the resource that was blocked from loading by the Content Security Policy. If the blocked URI is from a different origin than the document-uri, then the blocked URI is truncated to contain just the scheme, host, and port.
	Disposition        string `json:"disposition"`         // Either "enforce" or "report" depending on whether the Content-Security-Policy header or the Content-Security-Policy-Report-Only header is used.
	DocumentURI        string `json:"document-uri"`        // The URI of the document in which the violation occurred.
	EffectiveDirective string `json:"effective-directive"` // The directive whose enforcement caused the violation.
	OriginalPolicy     string `json:"original-policy"`     // The original policy as specified by the Content-Security-Policy-Report-Only HTTP header.
	Referrer           string `json:"referrer"`            // The referrer of the document in which the violation occurred.
	ScriptSample       string `json:"script-sample"`       // The first 40 characters of the inline script, event handler, or style that caused the violation.
	StatusCode         int    `json:"status-code"`         // The HTTP status code of the resource on which the global object was instantiated.
	ViolatedDirective  string `json:"violated-directive"`  // The name of the policy section that was violated.
}
