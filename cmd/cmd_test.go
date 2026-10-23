package cmd

import (
	"reflect"
	"testing"
)

func TestRewriteLegacy(t *testing.T) {
	got := rewriteLegacy([]string{"-d", "example.com", "-oj", "-sv", "-he", "-zap", "-wl", "w.txt", "-p", "22,80"})
	want := []string{"-d", "example.com", "--outjson", "--service-version", "--http-evidence", "--zap", "--wordlist", "w.txt", "-p", "22,80"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	got = rewriteLegacy([]string{"--", "-oj"})
	if got[1] != "-oj" {
		t.Errorf("args after -- must be untouched: %v", got)
	}
}

func TestImpliedFlags(t *testing.T) {
	s := newScanCmd()
	if err := s.cmd.ParseFlags(rewriteLegacy([]string{"-d", "x.com", "-vwl", "w.txt", "--nse-scripts", "safe", "--zap-max-endpoints", "3", "--nuclei-severities", "high"})); err != nil {
		t.Fatal(err)
	}
	cfg := *s.cfg
	applyImplied(s.cmd, &cfg)
	if !cfg.Vhosts || !cfg.NSE || !cfg.Zap || !cfg.Nuclei {
		t.Errorf("implied flags not applied: %+v", cfg)
	}
}
