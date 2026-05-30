package dns

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/server/account"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// nameserversHandler is the nameserver group handler of the account
type nameserversHandler struct {
	accountManager account.Manager
}

func addDNSNameserversEndpoint(accountManager account.Manager, router *mux.Router) {
	nameserversHandler := newNameserversHandler(accountManager)
	router.HandleFunc("/dns/nameservers", nameserversHandler.getAllNameservers).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers", nameserversHandler.createNameserverGroup).Methods("POST", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.updateNameserverGroup).Methods("PUT", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.getNameserverGroup).Methods("GET", "OPTIONS")
	router.HandleFunc("/dns/nameservers/{nsgroupId}", nameserversHandler.deleteNameserverGroup).Methods("DELETE", "OPTIONS")
}

// newNameserversHandler returns a new instance of nameserversHandler handler
func newNameserversHandler(accountManager account.Manager) *nameserversHandler {
	return &nameserversHandler{accountManager: accountManager}
}

// getAllNameservers returns the list of nameserver groups for the account
func (h *nameserversHandler) getAllNameservers(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		log.WithContext(r.Context()).Error(err)
		http.Redirect(w, r, "/", http.StatusInternalServerError)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	nsGroups, err := h.accountManager.ListNameServerGroups(r.Context(), accountID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	apiNameservers := make([]*api.NameserverGroup, 0)
	for _, r := range nsGroups {
		apiNameservers = append(apiNameservers, toNameserverGroupResponse(r))
	}

	util.WriteJSONObject(r.Context(), w, apiNameservers)
}

// createNameserverGroup handles nameserver group creation request
func (h *nameserversHandler) createNameserverGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	var req api.PostApiDnsNameserversJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	nsGroup, err := h.accountManager.CreateNameServerGroup(r.Context(), accountID, req.Name, req.Description, nsList, req.Groups, req.Primary, req.Domains, req.Enabled, userID, req.SearchDomainsEnabled)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// updateNameserverGroup handles update to a nameserver group identified by a given ID
func (h *nameserversHandler) updateNameserverGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	var req api.PutApiDnsNameserversNsgroupIdJSONRequestBody
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		util.WriteErrorResponse("couldn't parse JSON request", http.StatusBadRequest, w)
		return
	}

	nsList, err := toServerNSList(req.Nameservers)
	if err != nil {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid NS servers format"), w)
		return
	}

	updatedNSGroup := &nbdns.NameServerGroup{
		ID:                   nsGroupID,
		Name:                 req.Name,
		Description:          req.Description,
		Primary:              req.Primary,
		Domains:              req.Domains,
		NameServers:          nsList,
		Groups:               req.Groups,
		Enabled:              req.Enabled,
		SearchDomainsEnabled: req.SearchDomainsEnabled,
	}

	err = h.accountManager.SaveNameServerGroup(r.Context(), accountID, userID, updatedNSGroup)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(updatedNSGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

// deleteNameserverGroup handles nameserver group deletion request
func (h *nameserversHandler) deleteNameserverGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	err = h.accountManager.DeleteNameServerGroup(r.Context(), accountID, nsGroupID, userID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	util.WriteJSONObject(r.Context(), w, util.EmptyObject{})
}

// getNameserverGroup handles a nameserver group Get request identified by ID
func (h *nameserversHandler) getNameserverGroup(w http.ResponseWriter, r *http.Request) {
	userAuth, err := nbcontext.GetUserAuthFromContext(r.Context())
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	accountID, userID := userAuth.AccountId, userAuth.UserId

	nsGroupID := mux.Vars(r)["nsgroupId"]
	if len(nsGroupID) == 0 {
		util.WriteError(r.Context(), status.Errorf(status.InvalidArgument, "invalid nameserver group ID"), w)
		return
	}

	nsGroup, err := h.accountManager.GetNameServerGroup(r.Context(), accountID, userID, nsGroupID)
	if err != nil {
		util.WriteError(r.Context(), err, w)
		return
	}

	resp := toNameserverGroupResponse(nsGroup)

	util.WriteJSONObject(r.Context(), w, &resp)
}

func toServerNSList(apiNSList []api.Nameserver) ([]nbdns.NameServer, error) {
	var nsList []nbdns.NameServer
	for _, apiNS := range apiNSList {
		nsURL, err := apiNameserverToURL(apiNS)
		if err != nil {
			return nil, err
		}
		parsed, err := nbdns.ParseNameServerURL(nsURL)
		if err != nil {
			return nil, err
		}
		nsList = append(nsList, parsed)
	}

	return nsList, nil
}

// apiNameserverToURL converts an API nameserver entry to the scheme-prefixed
// form expected by nbdns.ParseNameServerURL. It validates that fields required
// by each type are present.
func apiNameserverToURL(apiNS api.Nameserver) (string, error) {
	switch apiNS.NsType {
	case api.NameserverNsTypeUdp:
		if apiNS.Ip == nil || *apiNS.Ip == "" {
			return "", fmt.Errorf("udp nameserver requires ip")
		}
		if apiNS.Port == nil {
			return "", fmt.Errorf("udp nameserver requires port")
		}
		host, err := unwrapBracketedHost(*apiNS.Ip)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("udp://%s", net.JoinHostPort(host, strconv.Itoa(*apiNS.Port))), nil
	case api.NameserverNsTypeDoh:
		if apiNS.Url == nil || *apiNS.Url == "" {
			return "", fmt.Errorf("doh nameserver requires url")
		}
		// Accept full URL with scheme; rewrite to doh:// for ParseNameServerURL.
		u := *apiNS.Url
		switch {
		case strings.HasPrefix(u, "https://"):
			return "doh://" + strings.TrimPrefix(u, "https://"), nil
		case strings.HasPrefix(u, "doh://"):
			return u, nil
		default:
			return "", fmt.Errorf("doh nameserver url must start with https://")
		}
	case api.NameserverNsTypeNextdns:
		if apiNS.Url == nil || *apiNS.Url == "" {
			return "", fmt.Errorf("nextdns nameserver requires url with config id")
		}
		return "nextdns://" + *apiNS.Url, nil
	default:
		return "", fmt.Errorf("unknown nameserver type %q", apiNS.NsType)
	}
}

// unwrapBracketedHost returns ip with surrounding brackets stripped, rejecting
// inputs with mismatched brackets.
func unwrapBracketedHost(ip string) (string, error) {
	if !strings.ContainsAny(ip, "[]") {
		return ip, nil
	}
	if !strings.HasPrefix(ip, "[") || !strings.HasSuffix(ip, "]") {
		return "", fmt.Errorf("malformed bracketed address: %s", ip)
	}
	return ip[1 : len(ip)-1], nil
}

func toNameserverGroupResponse(serverNSGroup *nbdns.NameServerGroup) *api.NameserverGroup {
	var nsList []api.Nameserver
	for _, ns := range serverNSGroup.NameServers {
		apiNS := api.Nameserver{
			NsType: api.NameserverNsType(ns.NSType.String()),
		}
		switch ns.NSType {
		case nbdns.UDPNameServerType:
			ip := ns.IP.String()
			port := ns.Port
			apiNS.Ip = &ip
			apiNS.Port = &port
		case nbdns.DoHNameServerType, nbdns.NextDNSNameServerType:
			url := ns.URL
			apiNS.Url = &url
		}
		nsList = append(nsList, apiNS)
	}

	return &api.NameserverGroup{
		Id:                   serverNSGroup.ID,
		Name:                 serverNSGroup.Name,
		Description:          serverNSGroup.Description,
		Primary:              serverNSGroup.Primary,
		Domains:              serverNSGroup.Domains,
		Groups:               serverNSGroup.Groups,
		Nameservers:          nsList,
		Enabled:              serverNSGroup.Enabled,
		SearchDomainsEnabled: serverNSGroup.SearchDomainsEnabled,
	}
}
