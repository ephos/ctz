// Package ipinfo queries the ipinfo.io Lite API.
package ipinfo

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Client looks up IP metadata with caching.
type Client struct {
	Key     string
	BaseURL string
	HTTP    *http.Client

	mu    sync.Mutex
	cache map[string]map[string]any
}

// New returns a Client for the given API key.
func New(key string) *Client {
	return &Client{
		Key: key, BaseURL: "https://api.ipinfo.io/lite/",
		HTTP: &http.Client{Timeout: 5 * time.Second}, cache: map[string]map[string]any{},
	}
}

// Lookup returns the ipinfo payload for ip, or nil on failure.
func (c *Client) Lookup(ctx context.Context, ip string) map[string]any {
	if c == nil || c.Key == "" {
		return nil
	}
	c.mu.Lock()
	if v, ok := c.cache[ip]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	var payload map[string]any
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+ip, nil)
	if err == nil {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Key)
		req.Header.Set("User-Agent", "connectivity-test-zone")
		if resp, err := c.HTTP.Do(req); err == nil {
			defer resp.Body.Close()
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				payload = nil
			}
		}
	}
	c.mu.Lock()
	c.cache[ip] = payload
	c.mu.Unlock()
	return payload
}
