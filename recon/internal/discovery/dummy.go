// Package discovery holds placeholder recon logic. This is NOT a real
// subfinder/tlsx/dnsx wrapper yet — just enough to prove the NATS transport
// and JSON serialization pipeline end to end.
package discovery

import (
	"errors"
	"net"

	"github.com/onixus/shapoclyack/recon/internal/models"
)

// ErrUnhandledSeedType is returned when Run doesn't recognize seed.Value well
// enough to do (even dummy) discovery — the caller should Term the
// originating NATS message rather than retry, since redelivery won't change
// the seed.
var ErrUnhandledSeedType = errors.New("unhandled seed type/value for dummy discovery")

// Run performs placeholder discovery. Only seed.Value == "example.com" is
// handled: it generates a dummy subdomain "mail.example.com" and resolves it.
//
// A DNS resolution failure is not treated as a fatal error here — it is
// reported via IsAlive=false plus metadata.resolve_error so the caller can
// still publish a successful ReconResult.
func Run(seed models.Seed) ([]models.Asset, error) {
	if seed.Value != "example.com" {
		return nil, ErrUnhandledSeedType
	}

	host := "mail.example.com"
	ips, err := net.LookupIP(host)

	meta := map[string]interface{}{}
	isAlive := err == nil && len(ips) > 0
	if err != nil {
		meta["resolve_error"] = err.Error()
	} else {
		addrs := make([]string, 0, len(ips))
		for _, ip := range ips {
			addrs = append(addrs, ip.String())
		}
		meta["resolved_ips"] = addrs
	}

	return []models.Asset{
		{
			AssetType:       "subdomain",
			Value:           host,
			DiscoveryMethod: "dummy-static",
			IsAlive:         isAlive,
			Metadata:        meta,
		},
	}, nil
}
