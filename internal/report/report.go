// Package report renders and saves the scan output.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"ctz/internal/config"
	"ctz/internal/model"
)

// JSON returns the indented plain JSON document (newline-terminated).
func JSON(out *model.Output) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes connectivity-results.json into dir (or ./ when empty).
func Save(out *model.Output, dir string) (string, error) {
	data, err := JSON(out)
	if err != nil {
		return "", err
	}
	path := "./" + config.JSONFilename
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		path = filepath.Join(strings.TrimRight(dir, "/"), config.JSONFilename)
	}
	return path, os.WriteFile(path, data, 0o644)
}

const (
	reset   = "\x1b[0m"
	blue    = "\x1b[1;34m"
	green   = "\x1b[0;32m"
	white   = "\x1b[0;39m"
	dim     = "\x1b[1;30m"
	bracket = "\x1b[1;39m"
)

var tokenRe = regexp.MustCompile(`^(\s*)("(?:[^"\\]|\\.)*")(:)?(.*)$`)

// Colorize applies jq -C style colors to indented JSON text.
func Colorize(data []byte) string {
	var b strings.Builder
	for _, line := range strings.SplitAfter(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\n")
		nl := line[len(trimmed):]
		if m := tokenRe.FindStringSubmatch(trimmed); m != nil {
			indent, str, colon, rest := m[1], m[2], m[3], m[4]
			b.WriteString(indent)
			if colon != "" {
				b.WriteString(blue + str + reset + bracket + ":" + reset)
			} else {
				b.WriteString(green + str + reset)
			}
			b.WriteString(colorRest(rest))
			b.WriteString(nl)
			continue
		}
		b.WriteString(colorRest(trimmed))
		b.WriteString(nl)
	}
	return b.String()
}

var scalarRe = regexp.MustCompile(`^(\s*)(.*?)(,?)$`)

func colorRest(s string) string {
	m := scalarRe.FindStringSubmatch(s)
	if m == nil {
		return s
	}
	ws, body, comma := m[1], m[2], m[3]
	switch {
	case body == "":
		return s
	case strings.HasPrefix(body, `"`):
		return fmt.Sprintf("%s%s%s%s%s", ws, green, body, reset, comma)
	case body == "null":
		return fmt.Sprintf("%s%s%s%s%s", ws, dim, body, reset, comma)
	case body == "{" || body == "[" || body == "}" || body == "]" || body == "{}" || body == "[]":
		return fmt.Sprintf("%s%s%s%s%s", ws, bracket, body, reset, comma)
	default:
		return fmt.Sprintf("%s%s%s%s%s", ws, white, body, reset, comma)
	}
}
