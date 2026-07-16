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

var (
	feedCache   *ThreatIntelFeed
	feedCacheMu sync.RWMutex
	feedCacheTTL = 1 * time.Hour
	feedCacheAt  time.Time
)

// LoadThreatIntelFeed fetches a JSON feed from a URL with in-memory caching.
func LoadThreatIntelFeed(url string) (*ThreatIntelFeed, error) {
	feedCacheMu.RLock()
	if feedCache != nil && time.Since(feedCacheAt) < feedCacheTTL {
		defer feedCacheMu.RUnlock()
		return feedCache, nil
	}
	feedCacheMu.RUnlock()

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

	feedCacheMu.Lock()
	feedCache = &feed
	feedCacheAt = time.Now()
	feedCacheMu.Unlock()

	return &feed, nil
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
