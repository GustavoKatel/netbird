package dns

import (
	"net/netip"
	"testing"
)

func TestParseNameServerURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    NameServer
		wantErr bool
	}{
		{
			name:  "udp",
			input: "udp://1.1.1.1:53",
			want: NameServer{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: UDPNameServerType,
				Port:   53,
			},
		},
		{
			name:  "doh url is normalized to https",
			input: "doh://dns.google/dns-query",
			want: NameServer{
				NSType: DoHNameServerType,
				URL:    "https://dns.google/dns-query",
			},
		},
		{
			name:  "doh with custom port and path",
			input: "doh://example.com:8443/resolve",
			want: NameServer{
				NSType: DoHNameServerType,
				URL:    "https://example.com:8443/resolve",
			},
		},
		{
			name:  "nextdns shorthand stores config id",
			input: "nextdns://abc123",
			want: NameServer{
				NSType: NextDNSNameServerType,
				URL:    "abc123",
			},
		},
		{
			name:    "unknown scheme rejected",
			input:   "ftp://1.2.3.4:53",
			wantErr: true,
		},
		{
			name:    "doh missing host rejected",
			input:   "doh:///dns-query",
			wantErr: true,
		},
		{
			name:    "nextdns missing id rejected",
			input:   "nextdns://",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseNameServerURL(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.IsEqual(&tt.want) {
				t.Fatalf("got %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestNameServerType_RoundTrip(t *testing.T) {
	for _, tc := range []NameServerType{UDPNameServerType, DoHNameServerType, NextDNSNameServerType} {
		got := ToNameServerType(tc.String())
		if got != tc {
			t.Errorf("round-trip mismatch for %v: got %v", tc, got)
		}
	}
}
