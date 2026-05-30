package dns

import (
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	// InvalidNameServerType invalid nameserver type
	InvalidNameServerType NameServerType = iota
	// UDPNameServerType udp nameserver type
	UDPNameServerType
	// DoHNameServerType DNS-over-HTTPS nameserver type. The full DoH URL is
	// stored on NameServer.URL; IP and Port are unused.
	DoHNameServerType
	// NextDNSNameServerType NextDNS DoH shorthand. NameServer.URL holds the
	// NextDNS profile/config ID; the client builds the full URL at query time
	// and appends device identification.
	NextDNSNameServerType
)

const (
	// MaxGroupNameChar maximum group name size
	MaxGroupNameChar = 40
	// InvalidNameServerTypeString invalid nameserver type as string
	InvalidNameServerTypeString = "invalid"
	// UDPNameServerTypeString udp nameserver type as string
	UDPNameServerTypeString = "udp"
	// DoHNameServerTypeString DoH nameserver type as string
	DoHNameServerTypeString = "doh"
	// NextDNSNameServerTypeString NextDNS nameserver type as string
	NextDNSNameServerTypeString = "nextdns"
)

// NameServerType nameserver type
type NameServerType int

// String returns nameserver type string
func (n NameServerType) String() string {
	switch n {
	case UDPNameServerType:
		return UDPNameServerTypeString
	case DoHNameServerType:
		return DoHNameServerTypeString
	case NextDNSNameServerType:
		return NextDNSNameServerTypeString
	default:
		return InvalidNameServerTypeString
	}
}

// ToNameServerType returns a nameserver type
func ToNameServerType(typeString string) NameServerType {
	switch typeString {
	case UDPNameServerTypeString:
		return UDPNameServerType
	case DoHNameServerTypeString:
		return DoHNameServerType
	case NextDNSNameServerTypeString:
		return NextDNSNameServerType
	default:
		return InvalidNameServerType
	}
}

// NameServerGroup group of nameservers and with group ids
type NameServerGroup struct {
	// ID identifier of group
	ID string `gorm:"primaryKey"`
	// AccountID is a reference to Account that this object belongs
	AccountID string `gorm:"index"`
	PublicID  string `json:"-"`
	// Name group name
	Name string
	// Description group description
	Description string
	// NameServers list of nameservers
	NameServers []NameServer `gorm:"serializer:json"`
	// Groups list of peer group IDs to distribute the nameservers information
	Groups []string `gorm:"serializer:json"`
	// Primary indicates that the nameserver group is the primary resolver for any dns query
	Primary bool
	// Domains indicate the dns query domains to use with this nameserver group
	Domains []string `gorm:"serializer:json"`
	// Enabled group status
	Enabled bool
	// SearchDomainsEnabled indicates whether to add match domains to search domains list or not
	SearchDomainsEnabled bool
}

// NameServer represents a DNS nameserver
type NameServer struct {
	// IP address of nameserver (UDP/DoT). Unset for DoH/NextDNS.
	IP netip.Addr
	// NSType nameserver type
	NSType NameServerType
	// Port nameserver listening port (UDP/DoT). Unset for DoH/NextDNS.
	Port int
	// URL is used for non-IP nameserver types. For DoH it stores the full
	// `https://...` endpoint; for NextDNS it stores the profile/config ID.
	URL string
}

// EventMeta returns activity event meta related to the nameserver group
func (g *NameServerGroup) EventMeta() map[string]any {
	return map[string]any{"name": g.Name}
}

// Copy copies a nameserver object
func (n *NameServer) Copy() *NameServer {
	return &NameServer{
		IP:     n.IP,
		NSType: n.NSType,
		Port:   n.Port,
		URL:    n.URL,
	}
}

// IsEqual compares one nameserver with the other
func (n *NameServer) IsEqual(other *NameServer) bool {
	return other.IP == n.IP &&
		other.NSType == n.NSType &&
		other.Port == n.Port &&
		other.URL == n.URL
}

// AddrPort returns the nameserver as a netip.AddrPort. Only meaningful for
// IP-based nameserver types (UDP/DoT).
func (n *NameServer) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(n.IP, uint16(n.Port))
}

// ParseNameServerURL parses a nameserver URL.
// Supported forms:
//
//	udp://<ip>:<port>            e.g. udp://1.1.1.1:53
//	doh://<host>[:<port>]/<path> e.g. doh://dns.google/dns-query
//	nextdns://<config_id>        e.g. nextdns://abc123
func ParseNameServerURL(nsURL string) (NameServer, error) {
	parsedURL, err := url.Parse(nsURL)
	if err != nil {
		return NameServer{}, err
	}
	var ns NameServer
	parsedScheme := strings.ToLower(parsedURL.Scheme)
	nsType := ToNameServerType(parsedScheme)
	if nsType == InvalidNameServerType {
		return NameServer{}, fmt.Errorf("invalid nameserver url schema type, got %s", parsedScheme)
	}
	ns.NSType = nsType

	switch nsType {
	case UDPNameServerType:
		parsedPort, err := strconv.Atoi(parsedURL.Port())
		if err != nil {
			return NameServer{}, fmt.Errorf("invalid nameserver url port, got %s", parsedURL.Port())
		}
		ns.Port = parsedPort

		parsedAddr, err := netip.ParseAddr(parsedURL.Hostname())
		if err != nil {
			return NameServer{}, fmt.Errorf("invalid nameserver url IP, got %s", parsedURL.Hostname())
		}
		ns.IP = parsedAddr

	case DoHNameServerType:
		if parsedURL.Host == "" {
			return NameServer{}, fmt.Errorf("doh nameserver url is missing host")
		}
		// Re-emit as https:// so the stored URL is directly usable by the client.
		dohURL := *parsedURL
		dohURL.Scheme = "https"
		ns.URL = dohURL.String()

	case NextDNSNameServerType:
		// Accept both nextdns://<id> (id parsed as host) and nextdns:<id>.
		configID := parsedURL.Host
		if configID == "" {
			configID = strings.TrimPrefix(parsedURL.Opaque, "/")
		}
		if configID == "" {
			return NameServer{}, fmt.Errorf("nextdns nameserver url is missing config id")
		}
		ns.URL = configID
	}

	return ns, nil
}

// Copy copies a nameserver group object
func (g *NameServerGroup) Copy() *NameServerGroup {
	nsGroup := &NameServerGroup{
		ID:                   g.ID,
		Name:                 g.Name,
		Description:          g.Description,
		NameServers:          make([]NameServer, len(g.NameServers)),
		Groups:               make([]string, len(g.Groups)),
		Enabled:              g.Enabled,
		Primary:              g.Primary,
		Domains:              make([]string, len(g.Domains)),
		SearchDomainsEnabled: g.SearchDomainsEnabled,
	}

	copy(nsGroup.NameServers, g.NameServers)
	copy(nsGroup.Groups, g.Groups)
	copy(nsGroup.Domains, g.Domains)

	return nsGroup
}

// IsEqual compares one nameserver group with the other
func (g *NameServerGroup) IsEqual(other *NameServerGroup) bool {
	return other.ID == g.ID &&
		other.Name == g.Name &&
		other.Description == g.Description &&
		other.Primary == g.Primary &&
		other.SearchDomainsEnabled == g.SearchDomainsEnabled &&
		compareNameServerList(g.NameServers, other.NameServers) &&
		compareGroupsList(g.Groups, other.Groups) &&
		compareGroupsList(g.Domains, other.Domains)
}

func compareNameServerList(list, other []NameServer) bool {
	if len(list) != len(other) {
		return false
	}

	for _, ns := range list {
		if !containsNameServer(ns, other) {
			return false
		}
	}

	return true
}

func containsNameServer(element NameServer, list []NameServer) bool {
	for _, ns := range list {
		if ns.IsEqual(&element) {
			return true
		}
	}
	return false
}

func compareGroupsList(list, other []string) bool {
	if len(list) != len(other) {
		return false
	}
	for _, id := range list {
		match := false
		for _, otherID := range other {
			if id == otherID {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}

	return true
}
