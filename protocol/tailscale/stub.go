//go:build !with_gvisor

package tailscale

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register(registry, C.TypeTailscale, NewEndpoint)
}

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
	return nil, E.New("Tailscale requires the 'with_gvisor' build tag")
}

func RegistryTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport(registry, C.DNSTypeTailscale, NewDNSTransport)
}

func NewDNSTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.TailscaleDNSServerOptions) (adapter.DNSTransport, error) {
	return nil, E.New("Tailscale requires the 'with_gvisor' build tag")
}
