//go:build !android && with_gvisor

package tailscale

import "github.com/sagernet/sing-box/adapter"

func setAndroidProtectFunc(platformInterface adapter.PlatformInterface) {
}
