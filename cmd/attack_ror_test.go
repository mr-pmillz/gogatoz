package cmd

import "testing"

func TestRorCallbackURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		webhookURL string
		actualAddr string
		want       string
	}{
		{
			name:       "base URL",
			webhookURL: "http://172.23.0.1:9444",
			want:       "http://172.23.0.1:9444/callback",
		},
		{
			name:       "documented callback URL",
			webhookURL: "http://172.23.0.1:9444/callback",
			want:       "http://172.23.0.1:9444/callback",
		},
		{
			name:       "listener fallback",
			actualAddr: "127.0.0.1:9444",
			want:       "http://127.0.0.1:9444/callback",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := rorCallbackURL(tt.webhookURL, tt.actualAddr); got != tt.want {
				t.Fatalf("rorCallbackURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
