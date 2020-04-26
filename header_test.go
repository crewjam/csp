package csp

import (
	"strconv"
	"testing"
)

func TestHeader(t *testing.T) {

	testCases := []struct {
		CSP   Header
		Value string
	}{
		{
			CSP:   Header{},
			Value: "",
		},
		{
			CSP: Header{
				DefaultSrc: []string{"*://*.example.com"},
			},
			Value: "default-src *://*.example.com",
		},
		{
			CSP: Header{
				BaseURI:                 []string{"BaseURI1", "BaseURI2"},
				BlockAllMixedContent:    true,
				ChildSrc:                []string{"ChildSrc1", "ChildSrc2"},
				ConnectSrc:              []string{"ConnectSrc1", "ConnectSrc2"},
				DefaultSrc:              []string{"DefaultSrc1", "DefaultSrc2"},
				FontSrc:                 []string{"FontSrc1", "FontSrc2"},
				FormAction:              []string{"FormAction1", "FormAction2"},
				FrameAncestors:          []string{"FrameAncestors1", "FrameAncestors2"},
				FrameSrc:                []string{"FrameSrc1", "FrameSrc2"},
				ImgSrc:                  []string{"ImgSrc1", "ImgSrc2"},
				ManifestSrc:             []string{"ManifestSrc1", "ManifestSrc2"},
				MediaSrc:                []string{"MediaSrc1", "MediaSrc2"},
				NavigateTo:              []string{"NavigateTo1", "NavigateTo2"},
				ObjectSrc:               []string{"ObjectSrc1", "ObjectSrc2"},
				PluginTypes:             []string{"PluginTypes1", "PluginTypes2"},
				PrefetchSrc:             []string{"PrefetchSrc1", "PrefetchSrc2"},
				Referrer:                NoReferrer,
				ReportTo:                "ReportTo",
				ReportURI:               "ReportURI",
				RequireSRIFor:           []RequireSRIFor{Script, Style},
				Sandbox:                 AllowDownloadsWithoutUserActivation,
				ScriptSrc:               []string{"ScriptSrc1", "ScriptSrc2"},
				ScriptSrcAttr:           []string{"ScriptSrcAttr1", "ScriptSrcAttr2"},
				ScriptSrcElem:           []string{"ScriptSrcElem1", "ScriptSrcElem2"},
				StyleSrc:                []string{"StyleSrc1", "StyleSrc2"},
				StyleSrcAttr:            []string{"StyleSrcAttr1", "StyleSrcAttr2"},
				StyleSrcElem:            []string{"StyleSrcElem1", "StyleSrcElem2"},
				TrustedTypes:            []string{"TrustedTypes1", "TrustedTypes2"},
				UpgradeInsecureRequests: true,
				WorkerSrc:               []string{"WorkerSrc1", "WorkerSrc2"},
			},
			Value: "base-uri BaseURI1 BaseURI2; " +
				"block-all-mixed-content; " +
				"child-src ChildSrc1 ChildSrc2; " +
				"connect-src ConnectSrc1 ConnectSrc2; " +
				"default-src DefaultSrc1 DefaultSrc2; " +
				"font-src FontSrc1 FontSrc2; " +
				"form-action FormAction1 FormAction2; " +
				"frame-ancestors FrameAncestors1 FrameAncestors2; " +
				"frame-src FrameSrc1 FrameSrc2; " +
				"img-src ImgSrc1 ImgSrc2; " +
				"manifest-src ManifestSrc1 ManifestSrc2; " +
				"media-src MediaSrc1 MediaSrc2; " +
				"navigate-to NavigateTo1 NavigateTo2; " +
				"object-src ObjectSrc1 ObjectSrc2; " +
				"plugin-types PluginTypes1 PluginTypes2; " +
				"prefetch-src PrefetchSrc1 PrefetchSrc2; " +
				"referrer no-referrer; " +
				"report-to ReportTo; " +
				"report-uri ReportURI; " +
				"require-sri-for script style; " +
				"sandbox allow-downloads-without-user-activation; " +
				"script-src ScriptSrc1 ScriptSrc2; " +
				"script-src-attr ScriptSrcAttr1 ScriptSrcAttr2; " +
				"script-src-elem ScriptSrcElem1 ScriptSrcElem2; " +
				"style-src StyleSrc1 StyleSrc2; " +
				"style-src-attr StyleSrcAttr1 StyleSrcAttr2; " +
				"style-src-elem StyleSrcElem1 StyleSrcElem2; " +
				"trusted-types TrustedTypes1 TrustedTypes2; " +
				"upgrade-insecure-requests; " +
				"worker-src WorkerSrc1 WorkerSrc2",
		},
	}

	for i, testCase := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {

			v := testCase.CSP.String()
			if v != testCase.Value {
				t.Errorf("%+v: expected %q got %q",
					testCase.CSP, testCase.Value, v)
			}

		})
	}

}
