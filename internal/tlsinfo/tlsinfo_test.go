package tlsinfo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestExpiration(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	s, expired, soon, days := Expiration(time.Date(2026, 12, 15, 23, 59, 59, 0, time.UTC), now)
	if s != "December 15, 2026 at 11:59:59 PM UTC" || expired || soon || days != 197 {
		t.Errorf("%q %v %v %d", s, expired, soon, days)
	}
	_, expired, soon, _ = Expiration(now.AddDate(0, 0, 10), now)
	if expired || !soon {
		t.Error("10 days out should be 'soon'")
	}
	_, expired, soon, _ = Expiration(now.AddDate(0, 0, -1), now)
	if !expired || soon {
		t.Error("past date should be expired")
	}
}

func TestReadAndScan(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	certs := Scan(context.Background(), "127.0.0.1", []int{port, port})
	if len(certs) != 1 {
		t.Fatalf("want 1 deduped cert, got %d", len(certs))
	}
	c := certs[0]
	if len(c.Ports) != 2 || len(c.Thumbprint) != 64 || c.Thumbprint != upper(c.Thumbprint) {
		t.Errorf("unexpected cert: %+v", c)
	}
	if c.Issuer == "" || c.Subject == "" || c.DaysUntilExpiration == nil {
		t.Errorf("incomplete cert: %+v", c)
	}
	if Read(context.Background(), "127.0.0.1", 1) != nil {
		t.Error("closed port should yield nil")
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
