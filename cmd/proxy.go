package cmd

import (
	"strings"

	"github.com/mr-pmillz/gogatoz/pkg/gitlabx"
	"golang.org/x/net/proxy"
)

// appendSOCKS5Option adds the SOCKS5 proxy option to clOpts if configured.
func appendSOCKS5Option(clOpts []gitlabx.Option) []gitlabx.Option {
	addr := strings.TrimSpace(socks5Proxy)
	if addr == "" {
		return clOpts
	}
	var auth *proxy.Auth
	user := strings.TrimSpace(socks5User)
	pass := strings.TrimSpace(socks5Pass)
	if user != "" || pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	return append(clOpts, gitlabx.WithSOCKS5Proxy(addr, auth))
}
