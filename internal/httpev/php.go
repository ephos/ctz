package httpev

import (
	"fmt"
	"regexp"
	"strconv"

	"ctz/internal/model"
)

var phpBannerRe = regexp.MustCompile(`(?i)\bPHP/(\d+)\.(\d+)\.(\d+)`)

var phpFixed = map[[2]int]int{{8, 2}: 35, {8, 3}: 36, {8, 4}: 27, {8, 5}: 12}

var phpCVEs = []string{"CVE-2026-109618", "CVE-2026-109619"}

func inLegacyRange(b [2]int) bool {
	ge := b[0] > 5 || (b[0] == 5 && b[1] >= 4)
	le := b[0] < 8 || (b[0] == 8 && b[1] <= 1)
	return ge && le
}

// PHPBanner returns the first PHP version disclosed in the X-Powered-By or
// Server header, or "". headers keys are lower-case.
func PHPBanner(headers map[string]string) string {
	for _, header := range []string{"x-powered-by", "server"} {
		value := headers[header]
		for _, loc := range phpBannerRe.FindAllStringSubmatchIndex(value, -1) {
			if end := loc[1]; end < len(value) {
				if c := value[end]; c == '.' || (c >= '0' && c <= '9') {
					continue
				}
			}
			return value[loc[2]:loc[7]]
		}
	}
	return ""
}

// AssessPHPCVE is banner-only triage; it is neither exploit verification nor
// a patch inventory. headers keys are lower-case ("x-powered-by", "server").
func AssessPHPCVE(headers map[string]string) []model.PHPFinding {
	findings := []model.PHPFinding{}
	for _, header := range []string{"x-powered-by", "server"} {
		value := headers[header]
		for _, loc := range phpBannerRe.FindAllStringSubmatchIndex(value, -1) {
			// Emulates Python's (?![\d.]) lookahead, which RE2 lacks.
			if end := loc[1]; end < len(value) {
				if c := value[end]; c == '.' || (c >= '0' && c <= '9') {
					continue
				}
			}
			major, _ := strconv.Atoi(value[loc[2]:loc[3]])
			minor, _ := strconv.Atoi(value[loc[4]:loc[5]])
			patch, _ := strconv.Atoi(value[loc[6]:loc[7]])
			branch := [2]int{major, minor}
			fixed, hasFixed := phpFixed[branch]
			if !hasFixed && !inLegacyRange(branch) {
				continue
			}
			if hasFixed && patch >= fixed {
				continue
			}
			version := value[loc[2]:loc[7]]
			for _, cve := range phpCVEs {
				dup := false
				for _, f := range findings {
					if f.CVE == cve && f.Version == version {
						dup = true
						break
					}
				}
				if dup {
					continue
				}
				var fv *string
				if hasFixed {
					s := fmt.Sprintf("8.%d.%d", minor, fixed)
					fv = &s
				}
				findings = append(findings, model.PHPFinding{
					CVE:             cve,
					Version:         version,
					Assessment:      "potentially_affected",
					DetectionMethod: "http_version_banner",
					Header:          header,
					Value:           value,
					FixedVersion:    fv,
					Validation: "Verify the installed PHP package and vendor security advisory. " +
						"Banners may be stale or spoofed and vendor backports may fix older " +
						"versions. This check does not confirm exploitability.",
					Recommendation: "Install a vendor-patched PHP package or upgrade to a fixed supported release.",
				})
			}
		}
	}
	return findings
}
