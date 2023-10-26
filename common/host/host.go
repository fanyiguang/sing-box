package host

import "net/netip"

type Host struct {
	domain    string
	addresses []netip.Addr
}

func New(domain string, addresses []string) (*Host, error) {
	h := &Host{
		domain: domain,
	}
	for _, address := range addresses {
		addr, err := netip.ParseAddr(address)
		if err != nil {
			return nil, err
		}
		h.addresses = append(h.addresses, addr)
	}
	return h, nil
}

func (h *Host) Match(domain string) bool {
	return h.domain == domain
}

func (h *Host) Addresses() []netip.Addr {
	return h.addresses
}
