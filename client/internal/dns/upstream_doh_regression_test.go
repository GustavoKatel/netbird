package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDoHDNSServer(t *testing.T, handler dns.HandlerFunc) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	ready := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{PacketConn: pc, Handler: handler, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { assert.NoError(t, server.Shutdown()); assert.NoError(t, <-done) })
	return netip.MustParseAddrPort(pc.LocalAddr().String())
}
func testDoHDNSReply(w dns.ResponseWriter, r *dns.Msg, last byte) error {
	m := new(dns.Msg).SetReply(r)
	if r.Question[0].Qtype == dns.TypeA {
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0}, A: net.IPv4(203, 0, 113, last)}}
	}
	return w.WriteMsg(m)
}
func TestDoHBootstrapFailover(t *testing.T) {
	blackhole := testDoHDNSServer(t, func(dns.ResponseWriter, *dns.Msg) {})
	var hits atomic.Int32
	healthy := testDoHDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) { hits.Add(1); assert.NoError(t, testDoHDNSReply(w, r, 42)) })
	c := newDoHClient(nil)
	c.bootstrap = func() []netip.AddrPort { return []netip.AddrPort{blackhole, healthy} }
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	_, err := c.resolveBootstrap(ctx, "dns.example.com")
	t.Logf("healthy server query count: %d", hits.Load())
	require.NoError(t, err, "second working bootstrap should be attempted within request deadline")
}
func TestDoHBootstrapTTLZero(t *testing.T) {
	var last atomic.Uint32
	last.Store(42)
	server := testDoHDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) { assert.NoError(t, testDoHDNSReply(w, r, byte(last.Load()))) })
	c := newDoHClient(nil)
	c.bootstrap = func() []netip.AddrPort { return []netip.AddrPort{server} }
	first, err := c.resolveBootstrap(t.Context(), "dns.example.com")
	require.NoError(t, err)
	last.Store(43)
	second, err := c.resolveBootstrap(t.Context(), "dns.example.com")
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "a zero-TTL bootstrap answer must not be reused indefinitely")
}
func TestDoHRedirectDowngrade(t *testing.T) {
	var plaintext atomic.Bool
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plaintext.Store(true)
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		q := new(dns.Msg)
		assert.NoError(t, q.Unpack(body))
		m := new(dns.Msg).SetReply(q)
		out, err := m.Pack()
		assert.NoError(t, err)
		w.Header().Set("Content-Type", dohContentType)
		_, err = w.Write(out)
		assert.NoError(t, err)
	}))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusTemporaryRedirect)
	}))
	defer secure.Close()
	c := newDoHClient(nil)
	c.httpClient.Transport.(*http.Transport).TLSClientConfig = secure.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	_, _, err := c.exchange(t.Context(), upstreamTarget{NSType: nbdns.DoHNameServerType, URL: secure.URL}, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
	assert.Error(t, err, "HTTPS DoH must reject a redirect to plaintext HTTP")
	assert.False(t, plaintext.Load(), "DNS query must not be disclosed over plaintext")
}
func TestDoHBootstrapHostManagerRace(t *testing.T) {
	s := &DefaultServer{hostManager: &noopHostConfigurator{}}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			s.mux.Lock()
			s.hostManager = &noopHostConfigurator{}
			s.mux.Unlock()
		}
	}()
	for range 1000 {
		s.dohBootstrap()
	}
	<-done
}

func TestDoHResponseValidation(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		size        int
	}{
		{"wrong media type", "text/plain", 12},
		{"oversized message", dohContentType, dns.MaxMsgSize + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				_, err := w.Write(make([]byte, tc.size))
				assert.NoError(t, err)
			}))
			t.Cleanup(server.Close)
			c := newTestDoHClient(t, server)
			_, _, err := c.exchange(t.Context(), upstreamTarget{NSType: nbdns.DoHNameServerType, URL: server.URL}, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))
			require.Error(t, err)
		})
	}
}

func TestDoHEndpointValidation(t *testing.T) {
	c := newDoHClient(nil)
	for _, endpoint := range []string{"http://dns.example/query", "https://user:password@dns.example/query", "https://dns.example/query#fragment", "https:///query"} {
		_, err := c.endpointURL(upstreamTarget{NSType: nbdns.DoHNameServerType, URL: endpoint})
		require.Error(t, err, "invalid endpoint %q must be rejected", endpoint)
	}
}

func TestDoHBootstrapSnapshot(t *testing.T) {
	s := new(DefaultServer)
	servers := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53")}
	s.setDoHBootstrapServers(servers)
	servers[0] = netip.MustParseAddrPort("192.0.2.2:53")
	first := s.dohBootstrap()
	require.Equal(t, "192.0.2.1:53", first[0].String(), "caller must not mutate published snapshot")
	first[0] = servers[0]
	require.Equal(t, "192.0.2.1:53", s.dohBootstrap()[0].String(), "reader must not mutate published snapshot")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			s.setDoHBootstrapServers(servers)
		}
	}()
	for range 1000 {
		s.dohBootstrap()
	}
	<-done
	s.setDoHBootstrapServers(nil)
	assert.Empty(t, s.dohBootstrap(), "clearing DNS must release the snapshot")
}
