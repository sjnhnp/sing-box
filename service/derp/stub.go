//go:build !with_gvisor

package derp

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	boxService "github.com/sagernet/sing-box/adapter/service"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func Register(registry *boxService.Registry) {
	boxService.Register[option.DERPServiceOptions](registry, C.TypeDERP, NewService)
}

func NewService(ctx context.Context, logger log.ContextLogger, tag string, options option.DERPServiceOptions) (adapter.Service, error) {
	return nil, E.New("DERP service requires the 'with_gvisor' build tag")
}
