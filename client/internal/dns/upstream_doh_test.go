package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

// newTestDoHClient returns a dohClient whose Transport dials the given URL's
// host directly (no bootstrap resolution), suitable for httptest.Server.
func newTestDoHClient(t *testing.T, server *httptest.Server) *dohClient {
	t.Helper()
	c := newDoHClient(nil)
	c.httpClient = server.Client()
	return c
}

func TestDoHClient_Exchange_GenericDoH(t *testing.T) {
	question := "example.com."
	answer := "203.0.113.42"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, dohContentType, r.Header.Get("Content-Type"))
		assert.Empty(t, r.URL.RawQuery, "generic DoH must not inject device parameter")

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		req := new(dns.Msg)
		require.NoError(t, req.Unpack(body))
		require.Len(t, req.Question, 1)
		assert.Equal(t, question, req.Question[0].Name)

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: question, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP(answer),
			},
		}
		out, err := resp.Pack()
		require.NoError(t, err)

		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(out)
	}))
	defer server.Close()

	c := newTestDoHClient(t, server)
	target := upstreamTarget{NSType: nbdns.DoHNameServerType, URL: server.URL}

	q := new(dns.Msg).SetQuestion(question, dns.TypeA)
	resp, _, err := c.exchange(t.Context(), target, q)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)
	assert.Contains(t, resp.Answer[0].String(), answer)
}

func TestDoHClient_Exchange_NextDNS_URLAndHeaders(t *testing.T) {
	const fqdn = "laptop.peers.netbird.cloud"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "dns.nextdns.io", r.Host, "request must retain the NextDNS authority")
		assert.Equal(t, "/abc123", r.URL.Path, "profile must be in the request path")
		assert.Equal(t, fqdn, r.Header.Get("X-Device-Name"), "request must identify the device")
		assert.Equal(t, "laptop", r.Header.Get("X-Device-Id"), "request must carry the short device ID")
		body, err := io.ReadAll(r.Body)
		if !assert.NoError(t, err) {
			return
		}
		query := new(dns.Msg)
		if !assert.NoError(t, query.Unpack(body)) {
			return
		}
		response, err := new(dns.Msg).SetReply(query).Pack()
		if !assert.NoError(t, err) {
			return
		}
		w.Header().Set("Content-Type", dohContentType)
		_, err = w.Write(response)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)
	c := newDoHClient(nil)
	t.Cleanup(c.httpClient.CloseIdleConnections)
	c.deviceFn = func() string { return fqdn }
	transport := c.httpClient.Transport.(*http.Transport)
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, network, server.Listener.Addr().String())
	}
	_, _, err := c.exchange(t.Context(), upstreamTarget{NSType: nbdns.NextDNSNameServerType, URL: "abc123"}, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	require.NoError(t, err)
}

func TestNextDNSDeviceID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"laptop.peers.netbird.cloud", "laptop"},
		{"client-a.anon-abc.domain", "client-a"},
		{"justhostname", "justhostname"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, nextDNSDeviceID(tc.in))
		})
	}
}

func TestDoHClient_EndpointURL_Errors(t *testing.T) {
	c := newDoHClient(nil)

	_, err := c.endpointURL(upstreamTarget{NSType: nbdns.DoHNameServerType})
	assert.Error(t, err, "doh without URL should error")

	_, err = c.endpointURL(upstreamTarget{NSType: nbdns.NextDNSNameServerType})
	assert.Error(t, err, "nextdns without config id should error")

	_, err = c.endpointURL(upstreamTarget{NSType: nbdns.UDPNameServerType})
	assert.Error(t, err, "udp target should not be routed through dohClient")
}

func TestDoHClient_ResolveBootstrap_NoNameservers(t *testing.T) {
	c := newDoHClient(nil)

	_, err := c.resolveBootstrap(t.Context(), "dns.example.com")
	require.Error(t, err, "lookup with no bootstrap configured must fail loudly")
	assert.Contains(t, err.Error(), "no bootstrap nameservers")

	c.bootstrap = func() []netip.AddrPort { return nil }
	_, err = c.resolveBootstrap(t.Context(), "dns.example.com")
	require.Error(t, err, "empty bootstrap result must fail loudly")
	assert.Contains(t, err.Error(), "no bootstrap nameservers")
}

func TestDoHClient_ResolveBootstrap_UsesProvidedNameservers(t *testing.T) {
	for _, truncate := range []bool{false, true} {
		name := "UDP"
		if truncate {
			name = "TCP fallback"
		}
		t.Run(name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			packetConn, err := net.ListenPacket("udp", listener.Addr().String())
			require.NoError(t, err)
			t.Cleanup(func() { _ = packetConn.Close() })

			handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				resp := new(dns.Msg).SetReply(req)
				if _, udp := w.RemoteAddr().(*net.UDPAddr); udp && truncate {
					resp.Truncated = true
				} else if req.Question[0].Qtype == dns.TypeA {
					resp.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.IPv4(203, 0, 113, 42),
					}}
				}
				assert.NoError(t, w.WriteMsg(resp))
			})
			for _, server := range []*dns.Server{
				{PacketConn: packetConn, Handler: handler},
				{Listener: listener, Handler: handler},
			} {
				ready := make(chan struct{})
				done := make(chan error, 1)
				server.NotifyStartedFunc = func() { close(ready) }
				go func() { done <- server.ActivateAndServe() }()
				<-ready
				t.Cleanup(func() {
					assert.NoError(t, server.Shutdown())
					assert.NoError(t, <-done)
				})
			}
			c := newDoHClient(nil)
			bootstrapAddr := netip.MustParseAddrPort(listener.Addr().String())
			c.bootstrap = func() []netip.AddrPort { return []netip.AddrPort{bootstrapAddr} }
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			ips, err := c.resolveBootstrap(ctx, "dns.example.com")
			require.NoError(t, err)
			require.Len(t, ips, 1, "bootstrap must return the local server's A record")
			assert.Equal(t, netip.MustParseAddr("203.0.113.42"), ips[0], "bootstrap must use the configured nameserver")
		})
	}
}
