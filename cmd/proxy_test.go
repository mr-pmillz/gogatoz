package cmd

import (
	"testing"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
)

func TestAppendSOCKS5Option_Empty(t *testing.T) {
	// Reset global vars
	socks5Proxy = ""
	socks5User = ""
	socks5Pass = ""

	opts := []gitlabx.Option{gitlabx.WithRetry(1)}
	got := appendSOCKS5Option(opts)
	if len(got) != 1 {
		t.Fatalf("expected 1 option, got %d", len(got))
	}
}

func TestAppendSOCKS5Option_WithProxy(t *testing.T) {
	socks5Proxy = "127.0.0.1:1080"
	socks5User = ""
	socks5Pass = ""
	defer func() { socks5Proxy = "" }()

	opts := []gitlabx.Option{gitlabx.WithRetry(1)}
	got := appendSOCKS5Option(opts)
	if len(got) != 2 {
		t.Fatalf("expected 2 options, got %d", len(got))
	}
}

func TestAppendSOCKS5Option_WithAuth(t *testing.T) {
	socks5Proxy = "proxy.example:9050"
	socks5User = "alice"
	socks5Pass = "hunter2"
	defer func() {
		socks5Proxy = ""
		socks5User = ""
		socks5Pass = ""
	}()

	opts := []gitlabx.Option{}
	got := appendSOCKS5Option(opts)
	if len(got) != 1 {
		t.Fatalf("expected 1 option, got %d", len(got))
	}
}

func TestAppendSOCKS5Option_WhitespaceOnly(t *testing.T) {
	socks5Proxy = "   "
	defer func() { socks5Proxy = "" }()

	opts := []gitlabx.Option{}
	got := appendSOCKS5Option(opts)
	if len(got) != 0 {
		t.Fatalf("expected 0 options for whitespace proxy, got %d", len(got))
	}
}
