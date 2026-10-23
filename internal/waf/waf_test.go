package waf

import (
	"reflect"
	"testing"
)

func TestParseAndDetect(t *testing.T) {
	out := "banner text\n[{\"url\":\"https://x\",\"detected\":true,\"firewall\":\"Cloudfront\",\"manufacturer\":\"Amazon\"}]"
	payload, err := ParseJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	detected, products := Detection(payload)
	if !detected || !reflect.DeepEqual(products, []string{"Cloudfront (Amazon)"}) {
		t.Errorf("detected=%v products=%v", detected, products)
	}
}

func TestNoDetectionAndGeneric(t *testing.T) {
	payload, _ := ParseJSON(`[{"detected":false,"firewall":"None","manufacturer":"None"}]`)
	if d, p := Detection(payload); d || len(p) != 0 {
		t.Errorf("d=%v p=%v", d, p)
	}
	payload, _ = ParseJSON(`[{"detected":true,"firewall":"Generic"}]`)
	if d, p := Detection(payload); !d || len(p) != 0 {
		t.Errorf("generic should detect with no product: d=%v p=%v", d, p)
	}
	if _, err := ParseJSON("   "); err == nil {
		t.Error("empty output should error")
	}
	if _, err := ParseJSON("no json here"); err == nil {
		t.Error("non-json should error")
	}
}
