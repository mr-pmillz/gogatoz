package cmd

import "testing"

func TestValidateAPIListenSecurity(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		key     string
		wantErr bool
	}{
		{name: "ipv4 loopback", addr: "127.0.0.1:8088"},
		{name: "ipv6 loopback", addr: "[::1]:8088"},
		{name: "localhost", addr: "localhost:8088"},
		{name: "all interfaces without key", addr: ":8088", wantErr: true},
		{name: "public without key", addr: "0.0.0.0:8088", wantErr: true},
		{name: "all interfaces with key", addr: ":8088", key: "secret"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAPIListenSecurity(tt.addr, tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAPIListenSecurity(%q): err=%v wantErr=%t", tt.addr, err, tt.wantErr)
			}
		})
	}
}
