//go:build !with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
)

func registerQUICInbounds(registry *inbound.Registry) {}

func registerQUICOutbounds(registry *outbound.Registry) {}

func registerQUICTransports(registry *dns.TransportRegistry) {}

func registerQUICServices(registry *service.Registry) {}
