#!/bin/bash
# ============================================================================
# Dynamic Protocol Registry Generator
# Generates registry.go and quic.go based on selected protocols
# ============================================================================

set -euo pipefail

# Protocol flags (passed as environment variables)
PROTO_VLESS="${PROTO_VLESS:-true}"
PROTO_VMESS="${PROTO_VMESS:-true}"
PROTO_TROJAN="${PROTO_TROJAN:-true}"
PROTO_SHADOWSOCKS="${PROTO_SHADOWSOCKS:-true}"
PROTO_HYSTERIA2="${PROTO_HYSTERIA2:-true}"
PROTO_NAIVE="${PROTO_NAIVE:-true}"
PROTO_HYSTERIA="${PROTO_HYSTERIA:-false}"
PROTO_TUIC="${PROTO_TUIC:-false}"
PROTO_SHADOWTLS="${PROTO_SHADOWTLS:-false}"
PROTO_ANYTLS="${PROTO_ANYTLS:-false}"
PROTO_WIREGUARD="${PROTO_WIREGUARD:-false}"
PROTO_TAILSCALE="${PROTO_TAILSCALE:-false}"
PROTO_SSH="${PROTO_SSH:-false}"
PROTO_TOR="${PROTO_TOR:-false}"

OUTPUT_DIR="${OUTPUT_DIR:-.}"

# ============================================================================
# Generate registry.go
# ============================================================================
generate_registry() {
    cat > "${OUTPUT_DIR}/registry.go" << 'HEADER'
package include

import (
	"context"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/fakeip"
	"github.com/sagernet/sing-box/dns/transport/hosts"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
HEADER

    # Detect if certificate provider registry is supported (version >= 1.14.0)
    HAS_CERTIFICATE_PROVIDER=false
    if [ -d "adapter/certificate" ] || [ -d "../adapter/certificate" ] || [ -d "sing-box/adapter/certificate" ]; then
        HAS_CERTIFICATE_PROVIDER=true
    fi

    # Add protocol imports
    [[ "$PROTO_ANYTLS" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/anytls"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/block"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/direct"' >> "${OUTPUT_DIR}/registry.go"
    echo '	protocolDNS "github.com/sagernet/sing-box/protocol/dns"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/group"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/http"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/mixed"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_NAIVE" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/naive"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/redirect"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SHADOWSOCKS" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/shadowsocks"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SHADOWTLS" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/shadowtls"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/socks"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SSH" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/ssh"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_TOR" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/tor"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_TROJAN" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/trojan"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/protocol/tun"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VLESS" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/vless"' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VMESS" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/vmess"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/service/resolved"' >> "${OUTPUT_DIR}/registry.go"
    echo '	"github.com/sagernet/sing-box/service/ssmapi"' >> "${OUTPUT_DIR}/registry.go"
    if [[ "$HAS_CERTIFICATE_PROVIDER" == "true" ]]; then
        echo '	"github.com/sagernet/sing-box/adapter/certificate"' >> "${OUTPUT_DIR}/registry.go"
        echo '	originca "github.com/sagernet/sing-box/service/origin_ca"' >> "${OUTPUT_DIR}/registry.go"
    fi
    echo '	E "github.com/sagernet/sing/common/exceptions"' >> "${OUTPUT_DIR}/registry.go"
    echo ')' >> "${OUTPUT_DIR}/registry.go"
    echo '' >> "${OUTPUT_DIR}/registry.go"

    # Context function
    if [[ "$HAS_CERTIFICATE_PROVIDER" == "true" ]]; then
        cat >> "${OUTPUT_DIR}/registry.go" << 'CONTEXT'
func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry(), CertificateProviderRegistry())
}

func CertificateProviderRegistry() *certificate.Registry {
	registry := certificate.NewRegistry()

	registerACMECertificateProvider(registry)
	registerTailscaleCertificateProvider(registry)
	originca.RegisterCertificateProvider(registry)

	return registry
}

CONTEXT
    else
        cat >> "${OUTPUT_DIR}/registry.go" << 'CONTEXT'
func Context(ctx context.Context) context.Context {
	return box.Context(ctx, InboundRegistry(), OutboundRegistry(), EndpointRegistry(), DNSTransportRegistry(), ServiceRegistry())
}

CONTEXT
    fi

    # InboundRegistry function
    cat >> "${OUTPUT_DIR}/registry.go" << 'INBOUND_START'
func InboundRegistry() *inbound.Registry {
	registry := inbound.NewRegistry()

	tun.RegisterInbound(registry)
	redirect.RegisterRedirect(registry)
	redirect.RegisterTProxy(registry)
	direct.RegisterInbound(registry)

	socks.RegisterInbound(registry)
	http.RegisterInbound(registry)
	mixed.RegisterInbound(registry)

INBOUND_START

    [[ "$PROTO_SHADOWSOCKS" == "true" ]] && echo '	shadowsocks.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VMESS" == "true" ]] && echo '	vmess.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_TROJAN" == "true" ]] && echo '	trojan.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_NAIVE" == "true" ]] && echo '	naive.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SHADOWTLS" == "true" ]] && echo '	shadowtls.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VLESS" == "true" ]] && echo '	vless.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_ANYTLS" == "true" ]] && echo '	anytls.RegisterInbound(registry)' >> "${OUTPUT_DIR}/registry.go"

    cat >> "${OUTPUT_DIR}/registry.go" << 'INBOUND_END'

	registerQUICInbounds(registry)
	registerStubForRemovedInbounds(registry)

	return registry
}

INBOUND_END

    # OutboundRegistry function
    cat >> "${OUTPUT_DIR}/registry.go" << 'OUTBOUND_START'
func OutboundRegistry() *outbound.Registry {
	registry := outbound.NewRegistry()

	direct.RegisterOutbound(registry)

	block.RegisterOutbound(registry)
	protocolDNS.RegisterOutbound(registry)

	group.RegisterSelector(registry)
	group.RegisterURLTest(registry)

	socks.RegisterOutbound(registry)
	http.RegisterOutbound(registry)
OUTBOUND_START

    [[ "$PROTO_SHADOWSOCKS" == "true" ]] && echo '	shadowsocks.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VMESS" == "true" ]] && echo '	vmess.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_TROJAN" == "true" ]] && echo '	trojan.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_NAIVE" == "true" ]] && echo '	registerNaiveOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_TOR" == "true" ]] && echo '	tor.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SSH" == "true" ]] && echo '	ssh.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_SHADOWTLS" == "true" ]] && echo '	shadowtls.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_VLESS" == "true" ]] && echo '	vless.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"
    [[ "$PROTO_ANYTLS" == "true" ]] && echo '	anytls.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/registry.go"

    cat >> "${OUTPUT_DIR}/registry.go" << 'OUTBOUND_END'

	registerQUICOutbounds(registry)
	registerStubForRemovedOutbounds(registry)

	return registry
}

OUTBOUND_END

    # EndpointRegistry function
    cat >> "${OUTPUT_DIR}/registry.go" << 'ENDPOINT'
func EndpointRegistry() *endpoint.Registry {
	registry := endpoint.NewRegistry()

	registerWireGuardEndpoint(registry)
	registerTailscaleEndpoint(registry)

	return registry
}

ENDPOINT

    # DNSTransportRegistry function
    cat >> "${OUTPUT_DIR}/registry.go" << 'DNS'
func DNSTransportRegistry() *dns.TransportRegistry {
	registry := dns.NewTransportRegistry()

	transport.RegisterTCP(registry)
	transport.RegisterUDP(registry)
	transport.RegisterTLS(registry)
	transport.RegisterHTTPS(registry)
	hosts.RegisterTransport(registry)
	local.RegisterTransport(registry)
	fakeip.RegisterTransport(registry)
	resolved.RegisterTransport(registry)

	registerQUICTransports(registry)
	registerDHCPTransport(registry)
	registerTailscaleTransport(registry)

	return registry
}

DNS

    # ServiceRegistry function
    cat >> "${OUTPUT_DIR}/registry.go" << 'SERVICE'
func ServiceRegistry() *service.Registry {
	registry := service.NewRegistry()

	resolved.RegisterService(registry)
	ssmapi.RegisterService(registry)

	registerDERPService(registry)
	registerCCMService(registry)
	registerOCMService(registry)
	registerOOMKillerService(registry)

	return registry
}

SERVICE

    # Stub functions
    cat >> "${OUTPUT_DIR}/registry.go" << 'STUBS'
func registerStubForRemovedInbounds(registry *inbound.Registry) {
	inbound.Register[option.ShadowsocksInboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksInboundOptions) (adapter.Inbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
}

func registerStubForRemovedOutbounds(registry *outbound.Registry) {
	outbound.Register[option.ShadowsocksROutboundOptions](registry, C.TypeShadowsocksR, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.ShadowsocksROutboundOptions) (adapter.Outbound, error) {
		return nil, E.New("ShadowsocksR is deprecated and removed in sing-box 1.6.0")
	})
	outbound.Register[option.StubOptions](registry, C.TypeWireGuard, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.StubOptions) (adapter.Outbound, error) {
		return nil, E.New("WireGuard outbound is deprecated in sing-box 1.11.0 and removed in sing-box 1.13.0, use WireGuard endpoint instead")
	})
}
STUBS
}

# ============================================================================
# Generate quic.go
# ============================================================================
generate_quic() {
    cat > "${OUTPUT_DIR}/quic.go" << 'HEADER'
//go:build with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/quic"
HEADER

    [[ "$PROTO_HYSTERIA" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/hysteria"' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_HYSTERIA2" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/hysteria2"' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_NAIVE" == "true" ]] && echo '	_ "github.com/sagernet/sing-box/protocol/naive/quic"' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_TUIC" == "true" ]] && echo '	"github.com/sagernet/sing-box/protocol/tuic"' >> "${OUTPUT_DIR}/quic.go"
    echo '	_ "github.com/sagernet/sing-box/transport/v2rayquic"' >> "${OUTPUT_DIR}/quic.go"
    echo ')' >> "${OUTPUT_DIR}/quic.go"
    echo '' >> "${OUTPUT_DIR}/quic.go"

    # registerQUICInbounds
    echo 'func registerQUICInbounds(registry *inbound.Registry) {' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_HYSTERIA" == "true" ]] && echo '	hysteria.RegisterInbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_TUIC" == "true" ]] && echo '	tuic.RegisterInbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_HYSTERIA2" == "true" ]] && echo '	hysteria2.RegisterInbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    echo '}' >> "${OUTPUT_DIR}/quic.go"
    echo '' >> "${OUTPUT_DIR}/quic.go"

    # registerQUICOutbounds
    echo 'func registerQUICOutbounds(registry *outbound.Registry) {' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_HYSTERIA" == "true" ]] && echo '	hysteria.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_TUIC" == "true" ]] && echo '	tuic.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    [[ "$PROTO_HYSTERIA2" == "true" ]] && echo '	hysteria2.RegisterOutbound(registry)' >> "${OUTPUT_DIR}/quic.go"
    echo '}' >> "${OUTPUT_DIR}/quic.go"
    echo '' >> "${OUTPUT_DIR}/quic.go"

    # registerQUICTransports
    cat >> "${OUTPUT_DIR}/quic.go" << 'TRANSPORTS'
func registerQUICTransports(registry *dns.TransportRegistry) {
	quic.RegisterTransport(registry)
	quic.RegisterHTTP3Transport(registry)
}
TRANSPORTS
}

# ============================================================================
# Generate quic_stub.go (for builds without QUIC)
# ============================================================================
generate_quic_stub() {
    cat > "${OUTPUT_DIR}/quic_stub.go" << 'STUB'
//go:build !with_quic

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
)

func registerQUICInbounds(registry *inbound.Registry) {}

func registerQUICOutbounds(registry *outbound.Registry) {}

func registerQUICTransports(registry *dns.TransportRegistry) {}
STUB
}

# ============================================================================
# Generate protocol list for release notes
# ============================================================================
generate_protocol_list() {
    local protocols=""
    
    # Core protocols (always included)
    protocols="Direct, Block, DNS, Socks, HTTP, Mixed, Selector, URLTest"
    
    # Optional protocols
    [[ "$PROTO_VLESS" == "true" ]] && protocols="$protocols, VLESS"
    [[ "$PROTO_VMESS" == "true" ]] && protocols="$protocols, VMess"
    [[ "$PROTO_TROJAN" == "true" ]] && protocols="$protocols, Trojan"
    [[ "$PROTO_SHADOWSOCKS" == "true" ]] && protocols="$protocols, Shadowsocks"
    [[ "$PROTO_HYSTERIA2" == "true" ]] && protocols="$protocols, Hysteria2"
    [[ "$PROTO_NAIVE" == "true" ]] && protocols="$protocols, NaïveProxy"
    [[ "$PROTO_HYSTERIA" == "true" ]] && protocols="$protocols, Hysteria"
    [[ "$PROTO_TUIC" == "true" ]] && protocols="$protocols, TUIC"
    [[ "$PROTO_SHADOWTLS" == "true" ]] && protocols="$protocols, ShadowTLS"
    [[ "$PROTO_ANYTLS" == "true" ]] && protocols="$protocols, AnyTLS"
    [[ "$PROTO_WIREGUARD" == "true" ]] && protocols="$protocols, WireGuard"
    [[ "$PROTO_TAILSCALE" == "true" ]] && protocols="$protocols, Tailscale"
    [[ "$PROTO_SSH" == "true" ]] && protocols="$protocols, SSH"
    [[ "$PROTO_TOR" == "true" ]] && protocols="$protocols, Tor"
    
    echo "$protocols"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo "Generating protocol registry files..."
    echo "Output directory: ${OUTPUT_DIR}"
    echo ""
    echo "Protocol configuration:"
    echo "  VLESS:       $PROTO_VLESS"
    echo "  VMess:       $PROTO_VMESS"
    echo "  Trojan:      $PROTO_TROJAN"
    echo "  Shadowsocks: $PROTO_SHADOWSOCKS"
    echo "  Hysteria2:   $PROTO_HYSTERIA2"
    echo "  NaïveProxy:  $PROTO_NAIVE"
    echo "  Hysteria:    $PROTO_HYSTERIA"
    echo "  TUIC:        $PROTO_TUIC"
    echo "  ShadowTLS:   $PROTO_SHADOWTLS"
    echo "  AnyTLS:      $PROTO_ANYTLS"
    echo "  WireGuard:   $PROTO_WIREGUARD"
    echo "  Tailscale:   $PROTO_TAILSCALE"
    echo "  SSH:         $PROTO_SSH"
    echo "  Tor:         $PROTO_TOR"
    echo ""
    
    generate_registry
    generate_quic
    generate_quic_stub
    
    echo "Generated files:"
    ls -la "${OUTPUT_DIR}/"*.go
    
    echo ""
    echo "Included protocols: $(generate_protocol_list)"
    
    # Output for GitHub Actions
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        echo "protocols=$(generate_protocol_list)" >> "$GITHUB_OUTPUT"
    fi
}

main "$@"
