package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	nbnet "github.com/netbirdio/netbird/client/net"
	nbdns "github.com/netbirdio/netbird/dns"
)

const (
	dohContentType = "application/dns-message"
	nextdnsBaseURL = "https://dns.nextdns.io/"
	dohProtocol    = "doh"
)

// dohClient shares HTTP connections across DoH and NextDNS upstreams.
// Bootstrap resolution uses the original host nameservers to avoid querying
// NetBird's own resolver after it takes over system DNS.
type dohClient struct {
	httpClient *http.Client
	// deviceFn returns the device identifier appended to NextDNS requests.
	// Tests inject a stub; production wires it to the local peer FQDN.
	deviceFn func() string
	// bootstrap returns the nameservers to use for resolving DoH endpoint
	// hostnames. Set by the resolver after construction; without it the
	// client cannot resolve non-IP hosts.
	bootstrap func() []netip.AddrPort
}

func newDoHClient(statusRecorder *peer.Status) *dohClient {
	c := &dohClient{
		deviceFn: deviceFnFromStatus(statusRecorder),
	}
	c.httpClient = &http.Client{
		Timeout:       ClientTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
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

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != dohContentType {
		return nil, time.Since(start), fmt.Errorf("unexpected doh content type %q", resp.Header.Get("Content-Type"))
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize+1))
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("read doh response: %w", err)
	}

	if len(respBody) > dns.MaxMsgSize {
		return nil, time.Since(start), fmt.Errorf("doh response exceeds %d bytes", dns.MaxMsgSize)
	}
	rm := new(dns.Msg)
	if err := rm.Unpack(respBody); err != nil {
		return nil, time.Since(start), fmt.Errorf("unpack doh response: %w", err)
	}

	setUpstreamProtocol(ctx, dohProtocol)
	return rm, time.Since(start), nil
}

// endpointURL expands NextDNS profile IDs and validates encrypted endpoints.
func (c *dohClient) endpointURL(target upstreamTarget) (string, error) {
	switch target.NSType {
	case nbdns.DoHNameServerType:
		if target.URL == "" {
			return "", fmt.Errorf("doh upstream missing url")
		}
		endpoint, err := url.Parse(target.URL)
		if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
			return "", fmt.Errorf("invalid HTTPS doh endpoint")
		}
		return endpoint.String(), nil
	case nbdns.NextDNSNameServerType:
		if target.URL == "" {
			return "", fmt.Errorf("nextdns upstream missing config id")
		}
		if len(target.URL) != 6 || strings.ContainsAny(target.URL, "/?#%") {
			return "", fmt.Errorf("invalid nextdns config id")
		}
		for _, ch := range target.URL {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return "", fmt.Errorf("invalid nextdns config id")
			}
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

// NextDNS identifies devices through headers, as in nextdns/nextdns/resolver/doh.go.
// The short hostname keeps the device ID stable across account renames.
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

// dialContext uses the original nameservers and tunnel-bypassing sockets
// to avoid feeding an endpoint lookup back into the overlay DNS resolver.
func (c *dohClient) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	d := nbnet.NewDialer()
	d.Timeout = 5 * time.Second

	if _, err := netip.ParseAddr(host); err == nil {
		return d.DialContext(ctx, network, addr)
	}

	ips, err := c.resolveBootstrap(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for i, ip := range ips {
		attempt, cancel := dohAttemptContext(ctx, len(ips)-i)
		conn, err := d.DialContext(attempt, network, net.JoinHostPort(ip.String(), port))
		cancel()
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("dial %s: all bootstrap IPs failed: %w", addr, lastErr)
}

func (c *dohClient) resolveBootstrap(ctx context.Context, host string) ([]netip.Addr, error) {
	if c.bootstrap == nil {
		return nil, fmt.Errorf("bootstrap lookup %s: no bootstrap nameservers configured", host)
	}
	servers := c.bootstrap()
	if len(servers) == 0 {
		return nil, fmt.Errorf("bootstrap lookup %s: no bootstrap nameservers available", host)
	}

	var lookupErrs []error
	for i, server := range servers {
		bootstrapAddr := server.String()
		// Bootstrap connections must bypass the overlay, just like DoH connections.
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := nbnet.NewDialer()
				return d.DialContext(ctx, network, bootstrapAddr)
			},
		}

		attempt, cancel := dohAttemptContext(ctx, len(servers)-i+1)
		ips, err := resolver.LookupNetIP(attempt, "ip", host)
		cancel()
		if err != nil {
			lookupErrs = append(lookupErrs, fmt.Errorf("%s: %w", bootstrapAddr, err))
			continue
		}
		if len(ips) == 0 {
			lookupErrs = append(lookupErrs, fmt.Errorf("%s: no addresses", bootstrapAddr))
			continue
		}

		for i := range ips {
			ips[i] = ips[i].Unmap()
		}
		log.Debugf("doh bootstrap resolved %s to %v via %s", host, ips, bootstrapAddr)
		return ips, nil
	}

	return nil, fmt.Errorf("bootstrap lookup %s failed via %d nameservers: %w", host, len(servers), errors.Join(lookupErrs...))
}

// dohAttemptContext reserves time for later servers and the HTTPS connection.
func dohAttemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	timeout := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline)/time.Duration(remaining))
	}
	return context.WithTimeout(ctx, timeout)
}
