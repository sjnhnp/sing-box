//go:build with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
 // Removed: github.com/sagernet/sing-box/protocol/hysteria - not used
	"github.com/sagernet/sing-box/protocol/hysteria2"
	_ "github.com/sagernet/sing-box/protocol/naive/quic"
 // Removed: github.com/sagernet/sing-box/protocol/tuic - not used
	_ "github.com/sagernet/sing-box/transport/v2rayquic"
)

func registerQUICInbounds(registry *inbound.Registry) {
 // Removed: hysteria.RegisterInbound(registry)
 // Removed: tuic.RegisterInbound(registry)
	hysteria2.RegisterInbound(registry)
}

func registerQUICOutbounds(registry *outbound.Registry) {
 // Removed: hysteria.RegisterOutbound(registry)
 // Removed: tuic.RegisterOutbound(registry)
	hysteria2.RegisterOutbound(registry)
}

func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}

func registerQUICServices(registry *service.Registry) {
	hysteria2.RegisterRealmService(registry)
}
