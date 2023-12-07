// Package csp provides structures to add Content-Security-Policy headers to HTTP responses.
package csp

import (
	"reflect"
	"strings"
)

// Header describes a Content-Security-Policy header
type Header struct {
	BaseURI                 []string                 `csp:"base-uri"`
	BlockAllMixedContent    bool                     `csp:"block-all-mixed-content"`
	ChildSrc                []string                 `csp:"child-src"`
	ConnectSrc              []string                 `csp:"connect-src"`
	DefaultSrc              []string                 `csp:"default-src"`
	FontSrc                 []string                 `csp:"font-src"`
	FormAction              []string                 `csp:"form-action"`
	FrameAncestors          []string                 `csp:"frame-ancestors"`
	FrameSrc                []string                 `csp:"frame-src"`
	ImgSrc                  []string                 `csp:"img-src"`
	ManifestSrc             []string                 `csp:"manifest-src"`
	MediaSrc                []string                 `csp:"media-src"`
	NavigateTo              []string                 `csp:"navigate-to"`
	ObjectSrc               []string                 `csp:"object-src"`
	PluginTypes             []string                 `csp:"plugin-types"`
	PrefetchSrc             []string                 `csp:"prefetch-src"`
	Referrer                ReferrerPolicy           `csp:"referrer"`
	ReportTo                string                   `csp:"report-to"`
	ReportURI               string                   `csp:"report-uri"`
	RequireSRIFor           []RequireSRIFor          `csp:"require-sri-for"`
	RequireTrustedTypesFor  []RequireTrustedTypesFor `csp:"require-trusted-types-for"`
	Sandbox                 Sandbox                  `csp:"sandbox"`
	ScriptSrc               []string                 `csp:"script-src"`
	ScriptSrcAttr           []string                 `csp:"script-src-attr"`
	ScriptSrcElem           []string                 `csp:"script-src-elem"`
	StyleSrc                []string                 `csp:"style-src"`
	StyleSrcAttr            []string                 `csp:"style-src-attr"`
	StyleSrcElem            []string                 `csp:"style-src-elem"`
	TrustedTypes            []string                 `csp:"trusted-types"`
	UpgradeInsecureRequests bool                     `csp:"upgrade-insecure-requests"`
	WorkerSrc               []string                 `csp:"worker-src"`
}

// RequireSRIFor represents the possible values of the require-sri-for field
type RequireSRIFor string

const (
	// Script means to require SRI for scripts.
	Script RequireSRIFor = "script"

	// Style means to require SRI for style sheets.
	Style RequireSRIFor = "style"
)

// RequireTrustedTypesFor represents the possible values of the require-trusted-types-for field
type RequireTrustedTypesFor string

// RTTFScript sets the value "'script'" int the require-trusted-types-for field
const RTTFScript = "'script'"

// Sandbox represents the possible values of the sandbox field
type Sandbox string

const (
	// AllowDownloadsWithoutUserActivation allows for downloads to occur without a gesture from the user.
	AllowDownloadsWithoutUserActivation Sandbox = "allow-downloads-without-user-activation"

	// AllowForms allows the page to submit forms. If this keyword is not used, this operation is not allowed.
	AllowForms Sandbox = "allow-forms"

	// AllowModals allows the page to open modal windows.
	AllowModals Sandbox = "allow-modals"

	// AllowOrientationLock allows the page to disable the ability to lock the screen orientation.
	AllowOrientationLock Sandbox = "allow-orientation-lock"

	// AllowPointerLock allows the page to use the Pointer Lock API.
	AllowPointerLock Sandbox = "allow-pointer-lock"

	// AllowPopups allows popups (like from window.open, target="_blank", showModalDialog). If this keyword is not used, that functionality will silently fail.
	AllowPopups Sandbox = "allow-popups"

	// AllowPopupsToEscapeSandbox allows a sandboxed document to open new windows without forcing the sandboxing flags upon them. This will allow, for example, a third-party advertisement to be safely sandboxed without forcing the same restrictions upon a landing page.
	AllowPopupsToEscapeSandbox Sandbox = "allow-popups-to-escape-sandbox"

	// AllowPresentation allows embedders to have control over whether an iframe can start a presentation session.
	AllowPresentation Sandbox = "allow-presentation"

	// AllowSameOrigin allows the content to be treated as being from its normal origin. If this keyword is not used, the embedded content is treated as being from a unique origin.
	AllowSameOrigin Sandbox = "allow-same-origin"

	// AllowScripts allows the page to run scripts (but not create pop-up windows). If this keyword is not used, this operation is not allowed.
	AllowScripts Sandbox = "allow-scripts"

	// AllowStorageAccessByUserActivation aets the resource request access to the parent's storage capabilities with the Storage Access API.
	AllowStorageAccessByUserActivation Sandbox = "allow-storage-access-by-user-activation "

	// AllowTopNavigation allows the page to navigate (load) content to the top-level browsing context. If this keyword is not used, this operation is not allowed.
	AllowTopNavigation Sandbox = "allow-top-navigation"

	// AllowTopNavigationByUserActivation aets the resource navigate the top-level browsing context, but only if initiated by a user gesture.
	AllowTopNavigationByUserActivation Sandbox = "allow-top-navigation-by-user-activation"
)

// ReferrerPolicy represents the possible values of the referrer field
type ReferrerPolicy string

const (
	// NoReferrer means that the Referer header will be omitted entirely. No referrer information is sent
	// along with requests.
	NoReferrer ReferrerPolicy = "no-referrer"

	// NoneWhenDowngrade means that this is the user agent's default behavior if no policy is specified.
	// The origin is sent as referrer to a-priori as-much-secure destination (HTTPS->HTTPS), but isn't
	// sent to a less secure destination (HTTPS->HTTP).
	NoneWhenDowngrade ReferrerPolicy = "none-when-downgrade"

	// Origin means to only send the origin of the document as the referrer in all cases. The document
	// https://example.com/page.html will send the referrer https://example.com/.
	Origin ReferrerPolicy = "origin"

	// OriginWhenCrossOrigin means to send a full URL when performing a same-origin request, but only send the origin of
	// the document for other cases.
	OriginWhenCrossOrigin ReferrerPolicy = "origin-when-cross-origin"

	// UnsafeURL means to send a full URL (stripped from parameters) when performing a same-origin or cross-origin
	// request. This policy will leak origins and paths from TLS-protected resources to insecure origins. Carefully
	// consider the impact of this setting.
	UnsafeURL ReferrerPolicy = "unsafe-url"
)

// String returns a formatted CSP header value
func (csp Header) String() string {
	parts := []string{}
	v := reflect.ValueOf(csp)
	typ := v.Type()

	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Tag.Get("csp")
		fv := v.Field(i)
		if fv.Kind() == reflect.Bool {
			if fv.Bool() {
				parts = append(parts, name)
			}
			continue
		}
		if fv.Kind() == reflect.String && !fv.IsZero() {
			parts = append(parts, name+" "+fv.String())
			continue
		}
		if fv.Kind() == reflect.Slice && fv.Len() > 0 {
			values := make([]string, fv.Len())
			for i := 0; i < fv.Len(); i++ {
				values[i] = fv.Index(i).String()
			}

			parts = append(parts, name+" "+strings.Join(values, " "))
			continue
		}
	}

	return strings.Join(parts, "; ")
}
