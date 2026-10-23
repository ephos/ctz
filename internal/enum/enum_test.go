package enum

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"

	"ctz/internal/config"
	"ctz/internal/execx"
)

func TestFilterDomainHosts(t *testing.T) {
	got := FilterDomainHosts([]string{"A.Example.com.", "example.com", "evilexample.com", "x.example.org", ""}, "example.com")
	want := []string{"a.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestCandidates(t *testing.T) {
	got := Candidates([]string{"dc01", "# comment", "", "vpn.example.com", "example.com", "DC01."}, "example.com")
	want := []string{"dc01.example.com", "example.com", "vpn.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestVhostHosts(t *testing.T) {
	raw := "Found: admin.example.com Status: 200 [Size: 10]\nFound: nope.other.org\nFound: a.b.example.com"
	got := VhostHosts(raw, "example.com")
	want := []string{"a.b.example.com", "admin.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestDefaultWordlistEmbedded(t *testing.T) {
	if len(defaultVhostWordlist) == 0 {
		t.Error("embedded vhost wordlist is empty")
	}
}

func TestDefaultDNSWordlistEmbedded(t *testing.T) {
	if n := strings.Count(string(defaultDNSWordlist), "\n"); n < 1000 {
		t.Errorf("embedded DNS wordlist has %d lines", n)
	}
}

func TestDnsxDefaultWordlistUsesEmbedded(t *testing.T) {
	cfg := config.Default()
	cfg.Wordlist = config.DefaultWordlist
	var cand string
	run := func(ctx context.Context, name string, args ...string) (execx.Result, error) {
		for i, a := range args {
			if a == "-l" {
				b, err := os.ReadFile(args[i+1])
				if err != nil {
					t.Fatal(err)
				}
				cand = string(b)
			}
		}
		return execx.Result{}, nil
	}
	if _, err := Dnsx(context.Background(), run, &cfg, t.TempDir(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cand, "www.example.com") || strings.Count(cand, "\n") < 1000 {
		t.Errorf("candidates not built from embedded list (%d lines)", strings.Count(cand, "\n"))
	}
}
