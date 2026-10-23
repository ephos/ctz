package tlsinfo

import "encoding/asn1"

func asn1Unmarshal(b []byte, v any) ([]byte, error) { return asn1.Unmarshal(b, v) }
