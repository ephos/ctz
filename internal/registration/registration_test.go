package registration

import (
	"encoding/json"
	"testing"
)

func TestNormalizeWhoisServer(t *testing.T) {
	cases := map[string]string{
		"whois.example.com":            "whois.example.com",
		"https://whois.trustname.com/": "whois.trustname.com",
		" whois.example.com/path ":     "whois.example.com",
		"":                             "",
	}
	for in, want := range cases {
		if got := NormalizeWhoisServer(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestParseWhois(t *testing.T) {
	raw := "Registrar WHOIS Server: whois.namecheap.com\nRegistry Expiry Date: 2027-07-01T08:35:27Z\nRegistrant  Name: Redacted\nRegistrar: NAMECHEAP INC\n"
	m := ParseWhois(raw)
	if m["registrar_whois_server"] != "whois.namecheap.com" || m["expiration_date"] != "2027-07-01T08:35:27Z" ||
		m["registrant_name"] != "Redacted" || m["registrar"] != "NAMECHEAP INC" {
		t.Errorf("parsed %v", m)
	}
}

const rdapSample = `{
 "port43":"whois.example.net",
 "events":[{"eventAction":"registration","eventDate":"2020-01-01T00:00:00Z"},{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"},{"eventAction":"last changed","eventDate":"2024-01-01T00:00:00Z"}],
 "entities":[
  {"roles":["registrar"],"vcardArray":["vcard",[["fn",{}, "text","Example Registrar"],["url",{},"uri","https://registrar.example"]]]},
  {"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Jane"],["org",{},"text","Acme"],["tel",{},"text","+1.555"],["adr",{},"text",["","","1 Main St","Town","ST","12345","US"]]]]}
 ]}`

func TestFromRDAP(t *testing.T) {
	var p map[string]any
	if err := json.Unmarshal([]byte(rdapSample), &p); err != nil {
		t.Fatal(err)
	}
	f := FromRDAP(p)
	want := map[string]string{
		"registrar_whois_server": "whois.example.net", "creation_date": "2020-01-01T00:00:00Z",
		"expiration_date": "2030-01-01T00:00:00Z", "updated_date": "2024-01-01T00:00:00Z",
		"registrar": "Example Registrar", "registrar_url": "https://registrar.example",
		"registrant_name": "Jane", "registrant_organization": "Acme", "registrant_phone": "+1.555",
		"registrant_street": "1 Main St", "registrant_city": "Town", "registrant_state_province": "ST",
		"registrant_postal_code": "12345", "registrant_country": "US",
	}
	for k, v := range want {
		if f[k] != v {
			t.Errorf("%s = %q, want %q", k, f[k], v)
		}
	}
}

func TestBaseURL(t *testing.T) {
	var b map[string]any
	_ = json.Unmarshal([]byte(`{"services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],[["org"],["https://rdap.pir.org/"]]]}`), &b)
	if got := BaseURL(b, "www.example.com"); got != "https://rdap.verisign.com/com/v1" {
		t.Errorf("got %q", got)
	}
	if got := BaseURL(b, "example.xyz"); got != "" {
		t.Errorf("got %q", got)
	}
}
