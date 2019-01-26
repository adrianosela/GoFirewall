package firewall

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
)

// Firewall is a software defined, endpoint-selective firewall for HTTP servers
type Firewall struct {
	Rules Rules
	Log   bool
}

/*Rules represents the rules that the software defined firewall will
* accept or accept traffic
 */
type Rules struct {
	PathToNetblocks map[string][]net.IPNet
	FailOpen        bool
}

var (
	// ErrPathHasRule will be returned when the developer attempts to re-assign a rule to a path
	ErrPathHasRule = errors.New("path already has an associated list of trusted netblocks")
	// ErrCouldNotParseCIDR will be returned when the developer attempts to use an invalid CIDR for a rule
	ErrCouldNotParseCIDR = fmt.Errorf("could not parse CIDR")
	// ErrCouldNotReadSrc will be returned when the IP can't be determined from the http.Request
	ErrCouldNotReadSrc = errors.New("could not get source IP from http request")
)

// New is the no-argument constructor for the firewall object
func New() *Firewall {
	return &Firewall{
		Rules: Rules{
			FailOpen: false,
		},
	}
}

/*NewFirewall is the constructor for the firewall object given a rule map and two boleans:
* failOpen: - false (default) to drop all requests for paths with an undefined trusted netblock
*           - true to allow all traffic to such paths
* log: true to log all dropped requests
 */
func NewFirewall(rules map[string][]net.IPNet, failOpen, log bool) *Firewall {
	return &Firewall{
		Rules: Rules{
			PathToNetblocks: rules,
			FailOpen:        failOpen,
		},
		Log: log,
	}
}

// AddPathRule maps a list of trusted netblocks to a given path
func (fw *Firewall) AddPathRule(path string, networks []string) error {
	if _, exists := fw.Rules.PathToNetblocks[path]; exists {
		return ErrPathHasRule
	}
	// parse network CIDRs
	var trusted []net.IPNet
	for _, network := range networks {
		_, trustedNetblock, err := net.ParseCIDR(network)
		if err != nil {
			return fmt.Errorf("could not parse CIDR: %s", err)
		}
		trusted = append(trusted, *trustedNetblock)
	}
	// add trusted netblocks to path
	fw.Rules.PathToNetblocks[path] = trusted
	return nil
}

// Wrap the firewall around an HTTP handler function
func (fw *Firewall) Wrap(h func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// extract IP from http.Request
		srcIP := net.ParseIP(strings.Split(r.RemoteAddr, ":")[0])
		// get rule for path
		rule, hasRule := fw.Rules.PathToNetblocks[r.URL.Path]
		authorized := (hasRule && IPIsTrusted(rule, srcIP)) || (fw.Rules.FailOpen)
		if !authorized {
			log.Println(fmt.Sprintf("[FIREWALL] blocked request from %s for %s", srcIP.String(), r.URL.Path))
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		h(w, r)
	})
}

// IPIsTrusted checks whether an IP address is part of a list of trusted netblocks
func IPIsTrusted(trusted []net.IPNet, src net.IP) bool {
	if src == nil {
		return false
	}
	for _, netblock := range trusted {
		if netblock.Contains(src) {
			return true
		}
	}
	return false
}
