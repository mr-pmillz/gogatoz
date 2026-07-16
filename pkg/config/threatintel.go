package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// ThreatIntelFeed holds indicator lists loaded from a file or URL.
type ThreatIntelFeed struct {
	BlockedDomains []string  `json:"blocked_domains" yaml:"blocked_domains" mapstructure:"blocked_domains"`
	BlockedIPs     []string  `json:"blocked_ips" yaml:"blocked_ips" mapstructure:"blocked_ips"`
	BlockedHashes  []string  `json:"blocked_hashes" yaml:"blocked_hashes" mapstructure:"blocked_hashes"`
	UpdatedAt      time.Time `json:"updated_at" yaml:"updated_at"`
}

// ThreatIntelCache provides thread-safe caching for a threat intel feed.
type ThreatIntelCache struct {
	mu      sync.RWMutex
	feed    *ThreatIntelFeed
	fetchAt time.Time
	ttl     time.Duration
}

// NewThreatIntelCache creates a cache with the given TTL.
func NewThreatIntelCache(ttl time.Duration) *ThreatIntelCache {
	return &ThreatIntelCache{ttl: ttl}
}

// LoadURL fetches a JSON feed from a URL, returning cached data if fresh.
func (c *ThreatIntelCache) LoadURL(url string) (*ThreatIntelFeed, error) {
	c.mu.RLock()
	if c.feed != nil && time.Since(c.fetchAt) < c.ttl {
		defer c.mu.RUnlock()
		return c.feed, nil
	}
	c.mu.RUnlock()

	feed, err := fetchFeed(url)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.feed = feed
	c.fetchAt = time.Now()
	c.mu.Unlock()

	return feed, nil
}

func fetchFeed(url string) (*ThreatIntelFeed, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url) //nolint:gosec // user-provided URL for threat intel
	if err != nil {
		return nil, fmt.Errorf("fetch threat intel feed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("threat intel feed returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read threat intel feed: %w", err)
	}

	var feed ThreatIntelFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("parse threat intel feed: %w", err)
	}
	feed.UpdatedAt = time.Now()
	return &feed, nil
}

// LoadThreatIntelFeed fetches a JSON feed from a URL (convenience wrapper).
func LoadThreatIntelFeed(url string) (*ThreatIntelFeed, error) {
	return fetchFeed(url)
}

// LoadThreatIntelFile reads a JSON feed from a local file.
func LoadThreatIntelFile(path string) (*ThreatIntelFeed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read threat intel file: %w", err)
	}
	var feed ThreatIntelFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return nil, fmt.Errorf("parse threat intel file: %w", err)
	}
	feed.UpdatedAt = time.Now()
	return &feed, nil
}
