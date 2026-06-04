//go:build integration

package dns

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

// liveBootstrap returns a bootstrap callback that points at Cloudflare. The
// live tests need a way to resolve the DoH endpoint's hostname without
// depending on the host's pre-takeover DNS state (which production wires
// in but unit tests don't).
func liveBootstrap() func() []netip.AddrPort {
	return func() []netip.AddrPort {
		return []netip.AddrPort{
			netip.MustParseAddrPort("1.1.1.1:53"),
			netip.MustParseAddrPort("9.9.9.9:53"),
		}
	}
}

// TestDoHClient_Live_Cloudflare exercises a real DoH round trip against
// Cloudflare. Confirms TLS, HTTP/2, bootstrap resolution, packing, and
// parsing all work end-to-end. Build-tagged so CI without network access
// or against blocked egress doesn't fail.
//
// Run: go test -tags=integration -count=1 -run TestDoHClient_Live ./client/internal/dns/...
func TestDoHClient_Live_Cloudflare(t *testing.T) {
	c := newDoHClient(nil)
	c.bootstrap = liveBootstrap()

	target := upstreamTarget{
		NSType: nbdns.DoHNameServerType,
		URL:    "https://cloudflare-dns.com/dns-query",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, rtt, err := c.exchange(ctx, target, q)
	require.NoError(t, err, "live DoH exchange failed")
	require.NotNil(t, resp)
	assert.True(t, resp.Response, "response flag must be set")
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	assert.NotEmpty(t, resp.Answer, "expected at least one answer record")
	t.Logf("DoH cloudflare-dns.com rtt=%s answers=%d", rtt.Truncate(time.Millisecond), len(resp.Answer))
}

// TestDoHClient_Live_NextDNS_URLShape sanity-checks the NextDNS URL builder
// against a real NextDNS deployment by sending a query to their public
// "trial" configuration (no auth). We don't validate the device tag from
// here — that requires inspecting their dashboard — but a successful query
// proves the URL is well-formed and the path-routed config ID is accepted.
//
// Skipped automatically if the NETBIRD_TEST_NEXTDNS_CONFIG_ID env var is
// empty so the test can run in environments without a NextDNS profile.
func TestDoHClient_Live_NextDNS_URLShape(t *testing.T) {
	configID := envOrSkip(t, "NETBIRD_TEST_NEXTDNS_CONFIG_ID")

	c := newDoHClient(nil)
	c.bootstrap = liveBootstrap()
	c.deviceFn = func() string { return "netbird-doh-live-test" }

	target := upstreamTarget{
		NSType: nbdns.NextDNSNameServerType,
		URL:    configID,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	q := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	resp, rtt, err := c.exchange(ctx, target, q)
	require.NoError(t, err, "live NextDNS exchange failed")
	require.NotNil(t, resp)
	assert.True(t, resp.Response)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "expected NOERROR, got %s", dns.RcodeToString[resp.Rcode])
	t.Logf("DoH dns.nextdns.io rtt=%s answers=%d (check the NextDNS dashboard for device=netbird-doh-live-test)",
		rtt.Truncate(time.Millisecond), len(resp.Answer))
}

func envOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping", key)
	}
	return v
}
