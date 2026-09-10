package networkmap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestDNSConfigForPeer(t *testing.T) {
	udp := &proto.NameServer{NSType: int64(nbdns.UDPNameServerType), IP: "192.0.2.1", Port: 53}
	doh := &proto.NameServer{NSType: int64(nbdns.DoHNameServerType), URL: "https://dns.example/query"}
	original := &proto.DNSConfig{
		ServiceEnable: true,
		NameServerGroups: []*proto.NameServerGroup{
			{NameServers: []*proto.NameServer{udp, doh}, Primary: true},
			{NameServers: []*proto.NameServer{doh}, Domains: []string{"example.com"}},
		},
	}
	legacy := DNSConfigForPeer(original, false)
	require.Len(t, legacy.NameServerGroups, 1, "old clients must not receive unsupported groups")
	assert.Equal(t, []*proto.NameServer{udp}, legacy.NameServerGroups[0].NameServers, "mixed groups must retain UDP")
	assert.True(t, legacy.NameServerGroups[0].Primary, "group properties must survive filtering")
	capable := DNSConfigForPeer(original, true)
	require.Len(t, capable.NameServerGroups, 2, "shared cached groups must remain intact for new clients")
	assert.Len(t, capable.NameServerGroups[0].NameServers, 2, "capable clients must receive encrypted upstreams")
}
