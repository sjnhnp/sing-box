//go:build with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
	// Removed: hysteria v1 - not used
	"github.com/sagernet/sing-box/protocol/hysteria2"
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
	// Removed: tuic - not used
	_ "github.com/sagernet/sing-box/transport/v2rayquic"
)

func registerQUICInbounds(registry *inbound.Registry) {
	// Removed: hysteria.RegisterInbound(registry) - not used
	// Removed: tuic.RegisterInbound(registry) - not used
	hysteria2.RegisterInbound(registry)
}

func registerQUICOutbounds(registry *outbound.Registry) {
	// Removed: hysteria.RegisterOutbound(registry) - not used
	// Removed: tuic.RegisterOutbound(registry) - not used
	hysteria2.RegisterOutbound(registry)
}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}
