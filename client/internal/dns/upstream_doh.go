package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	nbdns "github.com/netbirdio/netbird/dns"
)

const (
	dohContentType = "application/dns-message"
	nextdnsBaseURL = "https://dns.nextdns.io/"
	dohProtocol    = "doh"
)

// dohClient performs DoH (RFC 8484) exchanges. A single client is shared by
// every upstream that uses the DoH or NextDNS nameserver type.
//
// Bootstrap resolution: DoH endpoints are public hostnames (e.g.
// dns.nextdns.io). Resolving them through the OS resolver would loop when
// netbird itself is the OS resolver. The bootstrap callback returns the
// nameservers used to break that loop — typically the pre-takeover snapshot
// from hostManager.getOriginalNameservers(), filtered to drop our own
// service IP. The dohClient queries each in order until one answers and
// caches the result per host.
type dohClient struct {
	httpClient *http.Client
	// deviceFn returns the device identifier appended to NextDNS requests.
	// Tests inject a stub; production wires it to the local peer FQDN.
	deviceFn func() string
	// bootstrap returns the nameservers to use for resolving DoH endpoint
	// hostnames. Set by the resolver after construction; without it the
	// client cannot resolve non-IP hosts.
	bootstrap func() []netip.AddrPort

	bootstrapMu    sync.Mutex
	bootstrapCache map[string][]net.IP
}

func newDoHClient(statusRecorder *peer.Status) *dohClient {
	c := &dohClient{
		deviceFn:       deviceFnFromStatus(statusRecorder),
		bootstrapCache: make(map[string][]net.IP),
	}
	c.httpClient = &http.Client{
		Timeout: ClientTimeout,
		Transport: &http.Transport{
			DialContext:           c.dialContext,
			TLSHandshakeTimeout:   3 * time.Second,
			ResponseHeaderTimeout: ClientTimeout,
			ForceAttemptHTTP2:     true,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   2,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
	return c
}

func (c *dohClient) exchange(ctx context.Context, target upstreamTarget, r *dns.Msg) (*dns.Msg, time.Duration, error) {
	start := time.Now()

	endpoint, err := c.endpointURL(target)
	if err != nil {
		return nil, 0, err
	}

	body, err := r.Pack()
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("pack dns msg: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, time.Since(start), err
	}
	req.Header.Set("Content-Type", dohContentType)
	req.Header.Set("Accept", dohContentType)

	if target.NSType == nbdns.NextDNSNameServerType {
		c.setNextDNSDeviceHeaders(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("doh exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("doh status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("read doh response: %w", err)
	}

	rm := new(dns.Msg)
	if err := rm.Unpack(respBody); err != nil {
		return nil, time.Since(start), fmt.Errorf("unpack doh response: %w", err)
	}

	setUpstreamProtocol(ctx, dohProtocol)
	return rm, time.Since(start), nil
}

// endpointURL builds the request URL for the upstream. For NextDNS targets it
// expands the stored config ID into the canonical NextDNS URL. Device
// identification happens via HTTP headers in setNextDNSDeviceHeaders, not via
// the URL — NextDNS's official client uses X-Device-{Name,Id,Ip,Model} and
// ignores query parameters.
func (c *dohClient) endpointURL(target upstreamTarget) (string, error) {
	switch target.NSType {
	case nbdns.DoHNameServerType:
		if target.URL == "" {
			return "", fmt.Errorf("doh upstream missing url")
		}
		return target.URL, nil
	case nbdns.NextDNSNameServerType:
		if target.URL == "" {
			return "", fmt.Errorf("nextdns upstream missing config id")
		}
		return nextdnsBaseURL + target.URL, nil
	default:
		return "", fmt.Errorf("dohClient: unsupported nameserver type %s", target.NSType)
	}
}

func deviceFnFromStatus(statusRecorder *peer.Status) func() string {
	if statusRecorder == nil {
		return nil
	}
	return func() string { return statusRecorder.GetLocalPeerState().FQDN }
}

// setNextDNSDeviceHeaders adds NextDNS's per-request device identification
// headers. NextDNS uses X-Device-Name for the dashboard label and X-Device-Id
// as the stable per-device handle (queries with the same id are grouped
// together). We derive both from the local peer's FQDN: the full FQDN goes
// into the name (so it's recognizable), the short hostname into the id (so
// it survives FQDN suffix changes within an account).
//
// Reference: github.com/nextdns/nextdns/resolver/doh.go
func (c *dohClient) setNextDNSDeviceHeaders(req *http.Request) {
	if c.deviceFn == nil {
		return
	}
	fqdn := c.deviceFn()
	if fqdn == "" {
		return
	}
	req.Header.Set("X-Device-Name", fqdn)
	if id := nextDNSDeviceID(fqdn); id != "" {
		req.Header.Set("X-Device-Id", id)
	}
}

// nextDNSDeviceID returns the stable identifier sent as X-Device-Id. The
// short hostname (segment before the first dot) is stable across account
// renames and short enough for the NextDNS dashboard column.
func nextDNSDeviceID(fqdn string) string {
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}

// dialContext resolves the host using a fixed bootstrap nameserver and dials
// the resulting IP directly, bypassing the OS resolver.
func (c *dohClient) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 5 * time.Second}

	if ip := net.ParseIP(host); ip != nil {
		return d.DialContext(ctx, network, addr)
	}

	ips, err := c.resolveBootstrap(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("dial %s: all bootstrap IPs failed: %w", addr, lastErr)
}

func (c *dohClient) resolveBootstrap(ctx context.Context, host string) ([]net.IP, error) {
	c.bootstrapMu.Lock()
	if cached, ok := c.bootstrapCache[host]; ok {
		c.bootstrapMu.Unlock()
		return cached, nil
	}
	c.bootstrapMu.Unlock()

	if c.bootstrap == nil {
		return nil, fmt.Errorf("bootstrap lookup %s: no bootstrap nameservers configured", host)
	}
	servers := c.bootstrap()
	if len(servers) == 0 {
		return nil, fmt.Errorf("bootstrap lookup %s: no bootstrap nameservers available", host)
	}

	var lookupErrs []error
	for _, server := range servers {
		bootstrapAddr := server.String()
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", bootstrapAddr)
			},
		}

		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			lookupErrs = append(lookupErrs, fmt.Errorf("%s: %w", bootstrapAddr, err))
			continue
		}
		if len(ips) == 0 {
			lookupErrs = append(lookupErrs, fmt.Errorf("%s: no addresses", bootstrapAddr))
			continue
		}

		c.bootstrapMu.Lock()
		c.bootstrapCache[host] = ips
		c.bootstrapMu.Unlock()

		log.Debugf("doh bootstrap resolved %s to %v via %s", host, ips, bootstrapAddr)
		return ips, nil
	}

	return nil, fmt.Errorf("bootstrap lookup %s failed via %d nameservers: %w", host, len(servers), errors.Join(lookupErrs...))
}
