//go:build e2e

package dns_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestDoHManagementToClient(t *testing.T) {
	ctx := t.Context()
	// The fixture listens on the host's Docker bridge, reachable only from the lab.
	gateway, err := exec.CommandContext(ctx, "docker", "network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}").Output()
	require.NoError(t, err)
	ip := net.ParseIP(strings.TrimSpace(string(gateway)))
	require.NotNil(t, ip, "Docker bridge must have an address")
	cert, caPath := fixtureCertificate(t, ip)
	var queries atomic.Int32
	fixture := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, dns.MaxMsgSize+1))
		if !assert.NoError(t, err) {
			return
		}
		query := new(dns.Msg)
		if !assert.NoError(t, query.Unpack(body)) {
			return
		}
		response := new(dns.Msg).SetReply(query)
		if len(query.Question) > 0 && query.Question[0].Qtype == dns.TypeA {
			queries.Add(1)
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
				A:   net.IPv4(203, 0, 113, 42),
			}}
		}
		out, err := response.Pack()
		if !assert.NoError(t, err) {
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, err = w.Write(out)
		assert.NoError(t, err)
	}))
	require.NoError(t, fixture.Listener.Close())
	fixture.Listener, err = net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	require.NoError(t, err)
	fixture.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	fixture.StartTLS()
	t.Cleanup(fixture.Close)

	srv, err := harness.StartCombined(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, srv.Terminate(context.Background())) })
	_, err = srv.Bootstrap(ctx)
	require.NoError(t, err)
	group, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-doh"})
	require.NoError(t, err)
	key, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name: "e2e-doh", Type: "reusable", ExpiresIn: 86400, AutoGroups: []string{group.Id},
	})
	require.NoError(t, err)
	client, err := harness.StartClient(ctx, srv, key.Key, harness.WithClientRootCA(caPath))
	require.NoError(t, err)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(client.Logs(context.Background()))
		}
		assert.NoError(t, client.Terminate(context.Background()))
	})
	require.NoError(t, client.WaitConnected(ctx, 90*time.Second))

	endpoint := fixture.URL
	created, err := srv.API().DNS.CreateNameserverGroup(ctx, api.PostApiDnsNameserversJSONRequestBody{
		Name: "e2e-doh", Enabled: true, Groups: []string{group.Id}, Domains: []string{"doh-fixture.test"},
		Nameservers: []api.Nameserver{{NsType: api.NameserverNsType("doh"), Url: &endpoint}},
	})
	require.NoError(t, err)
	stored, err := srv.API().DNS.GetNameserverGroup(ctx, created.Id)
	require.NoError(t, err)
	require.Len(t, stored.Nameservers, 1, "management must persist the encrypted upstream")
	require.NotNil(t, stored.Nameservers[0].Url, "stored DoH nameserver must retain its URL")
	require.Equal(t, endpoint, *stored.Nameservers[0].Url, "management must retain the endpoint")
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		output, err := client.LookupDNS(ctx, "answer.doh-fixture.test")
		assert.NoError(c, err)
		assert.Contains(c, output, "203.0.113.42", "system resolver must receive the private fixture answer")
	}, 45*time.Second, time.Second, "management updates must reach the client's DNS resolver")
	assert.Positive(t, queries.Load(), "the configured TLS upstream must receive queries")
}

func fixtureCertificate(t *testing.T, ip net.IP) (tls.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "DoH E2E"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{ip}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, certPEM, 0600))
	return cert, path
}
