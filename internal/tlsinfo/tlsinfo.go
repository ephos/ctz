// Package tlsinfo reads TLS certificate metadata from open ports.
package tlsinfo

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"ctz/internal/model"
)

var oidNames = map[string]string{
	"2.5.4.3": "commonName", "2.5.4.6": "countryName", "2.5.4.7": "localityName", "2.5.4.8": "stateOrProvinceName",
	"2.5.4.9": "streetAddress", "2.5.4.10": "organizationName", "2.5.4.11": "organizationalUnitName",
	"2.5.4.5": "serialNumber", "2.5.4.17": "postalCode", "1.2.840.113549.1.9.1": "emailAddress",
}

// FormatName renders an X.509 name as "key=value, key=value" in encoded order,
// like the Python ssl module's decoded form flattened by the original script.
func FormatName(seq pkix.RDNSequence) string {
	var parts []string
	for _, rdn := range seq {
		for _, atv := range rdn {
			key := atv.Type.String()
			if n, ok := oidNames[key]; ok {
				key = n
			}
			parts = append(parts, key+"="+toString(atv.Value))
		}
	}
	return strings.Join(parts, ", ")
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Expiration computes the readable expiration and flags relative to now.
func Expiration(notAfter, now time.Time) (string, bool, bool, int) {
	notAfter = notAfter.UTC()
	days := int(notAfter.Sub(now).Hours() / 24)
	expired := notAfter.Before(now)
	return notAfter.Format("January 2, 2006 at 3:04:05 PM UTC"), expired, !expired && days <= 30, days
}

// Read performs a TLS handshake and returns the leaf certificate, or nil.
func Read(ctx context.Context, host string, port int) *model.TLSCertificate {
	d := net.Dialer{Timeout: 3 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host}) //nolint:gosec // inventory only
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil
	}
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	c := certs[0]
	exp, expired, soon, days := Expiration(c.NotAfter, time.Now())
	sum := sha256.Sum256(c.Raw)
	sans := c.DNSNames
	if sans == nil {
		sans = []string{}
	}
	var issuer, subject pkix.RDNSequence
	_, _ = asn1Unmarshal(c.RawIssuer, &issuer)
	_, _ = asn1Unmarshal(c.RawSubject, &subject)
	return &model.TLSCertificate{
		Ports:                   []int{port},
		Issuer:                  FormatName(issuer),
		Subject:                 FormatName(subject),
		SubjectAlternativeNames: sans,
		Thumbprint:              strings.ToUpper(hex.EncodeToString(sum[:])),
		Expiration:              exp,
		Expired:                 expired,
		ExpiresSoon:             soon,
		DaysUntilExpiration:     &days,
	}
}

// Scan reads certificates from every open port, deduplicating by thumbprint.
func Scan(ctx context.Context, host string, openPorts []int) []model.TLSCertificate {
	certs := []model.TLSCertificate{}
	idx := map[string]int{}
	for _, p := range openPorts {
		c := Read(ctx, host, p)
		if c == nil {
			continue
		}
		if i, ok := idx[c.Thumbprint]; ok {
			certs[i].Ports = append(certs[i].Ports, p)
			continue
		}
		idx[c.Thumbprint] = len(certs)
		certs = append(certs, *c)
	}
	return certs
}
