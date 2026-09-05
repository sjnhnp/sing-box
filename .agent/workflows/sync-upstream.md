---
description: Sync with upstream sing-box while intelligently preserving custom slim-down modifications (14 whitelist protocols).
---

# Smart Sync Upstream Workflow

此 workflow 用于同步上游 SagerNet/sing-box 的最新代码，采用**智能合并与 14 协议白名单精简策略**：

1. **保留上游变更**：默认接受上游的所有核心代码修复与底层网络库优化。
2. **严格保留 14 个协议**：
   `Direct`, `Block`, `DNS`, `Socks`, `HTTP`, `Mixed`, `Selector`, `URLTest`, `VLESS`, `VMess`, `Trojan`, `Shadowsocks`, `Hysteria2`, `NaïveProxy`。
3. **彻底切断幽灵依赖**：
   - 阻止 Hysteria2 源码中错误引用 TUIC。
   - 阻止 libbox 在 Android 下无条件链接 Tailscale。
   - 彻底移除 Snell, Bridge, WireGuard, OpenVPN, OpenConnect, ShadowTLS, AnyTLS, SSH, Tor, Hysteria (v1)。

---

## 执行步骤

### 1. 备份关键自定义文件

```powershell
$backupDir = Join-Path $env:TEMP "sing-box-backup"
if (Test-Path $backupDir) { Remove-Item -Recurse -Force $backupDir }
New-Item -ItemType Directory -Force -Path "$backupDir\.github\workflows" | Out-Null
New-Item -ItemType Directory -Force -Path "$backupDir\.github\scripts" | Out-Null
New-Item -ItemType Directory -Force -Path "$backupDir\include" | Out-Null
New-Item -ItemType Directory -Force -Path "$backupDir\experimental\libbox" | Out-Null
New-Item -ItemType Directory -Force -Path "$backupDir\protocol\hysteria2" | Out-Null

Copy-Item ".github\workflowsuild-slim.yml" -Destination "$backupDir\.github\workflowsuild-slim.yml"
Copy-Item ".github\workflows\sync-upstream-preserve.yml" -Destination "$backupDir\.github\workflows\sync-upstream-preserve.yml" -ErrorAction SilentlyContinue
Copy-Item ".github\scripts\generate-registry.sh" -Destination "$backupDir\.github\scripts\generate-registry.sh"
Copy-Item "README.md" -Destination "$backupDir\README.md" -ErrorAction SilentlyContinue
Copy-Item "include
egistry.go" -Destination "$backupDir\include
egistry.go"
Copy-Item "include\quic.go" -Destination "$backupDir\include\quic.go"
Copy-Item "include\quic_stub.go" -Destination "$backupDir\include\quic_stub.go"
Copy-Item "protocol\hysteria2\outbound.go" -Destination "$backupDir\protocol\hysteria2\outbound.go"
Copy-Item "experimental\libbox
ative_shell_session.go" -Destination "$backupDir\experimental\libbox
ative_shell_session.go"
Copy-Item "experimental\libbox
ative_shell_session_stub.go" -Destination "$backupDir\experimental\libbox
ative_shell_session_stub.go"

Write-Host "✅ Backup created at $backupDir"
```

### 2. 同步上游代码

使用 `-X theirs` 策略合并，优先合并上游的最新修改：

```bash
git remote add upstream https://github.com/SagerNet/sing-box.git 2>$null
git fetch upstream --tags
git merge upstream/testing -m "Merge upstream testing (Smart Sync)"
```

### 3. 恢复工作流、生成器及核心瘦身补丁

合并完成后，强制恢复工作流脚本与注册生成器，并应用 14 协议防泄露修复：

```powershell
$backupDir = Join-Path $env:TEMP "sing-box-backup"

# 1. 恢复 CI 配置与脚本
Copy-Item "$backupDir\.github\workflowsuild-slim.yml" -Destination ".github\workflowsuild-slim.yml" -Force
Copy-Item "$backupDir\.github\scripts\generate-registry.sh" -Destination ".github\scripts\generate-registry.sh" -Force
if (Test-Path "$backupDir\README.md") { Copy-Item "$backupDir\README.md" -Destination "README.md" -Force }

# 2. 核心补丁 A：防止 Hysteria2 意外带入 TUIC
$hy2Path = "protocol\hysteria2\outbound.go"
if (Test-Path $hy2Path) {
    $hy2Content = Get-Content $hy2Path -Raw
    $hy2Content = $hy2Content -replace '(?m)^\s*"github\.com/sagernet/sing-box/protocol/tuic"
?
', ''
    $hy2Content = $hy2Content.Replace('(*tuic.Outbound)(nil)', '(*Outbound)(nil)')
    Set-Content -Path $hy2Path -Value $hy2Content -NoNewline
    Write-Host "✅ Applied TUIC leak patch to Hysteria2"
}

# 3. 核心补丁 B：防止 Android libbox 意外带入 Tailscale
$nssPath = "experimental\libbox
ative_shell_session.go"
if (Test-Path $nssPath) {
    $nssContent = Get-Content $nssPath -Raw
    $nssContent = $nssContent -replace '//go:build linux \|\| android \|\| darwin \|\| ios', '//go:build (linux || android || darwin || ios) && with_tailscale'
    Set-Content -Path $nssPath -Value $nssContent -NoNewline
}
$nssStubPath = "experimental\libbox
ative_shell_session_stub.go"
if (Test-Path $nssStubPath) {
    $nssStubContent = Get-Content $nssStubPath -Raw
    $nssStubContent = $nssStubContent -replace '//go:build !linux && !android && !darwin && !ios', '//go:build (!linux && !android && !darwin && !ios) || !with_tailscale'
    Set-Content -Path $nssStubPath -Value $nssStubContent -NoNewline
    Write-Host "✅ Applied Tailscale leak patch to libbox"
}

# 4. 核心补丁 C：重新生成纯净的 14 协议 include/registry.go 与 include/quic.go
$env:PROTO_VLESS="true"
$env:PROTO_VMESS="true"
$env:PROTO_TROJAN="true"
$env:PROTO_SHADOWSOCKS="true"
$env:PROTO_HYSTERIA2="true"
$env:PROTO_NAIVE="true"
$env:PROTO_HYSTERIA="false"
$env:PROTO_TUIC="false"
$env:PROTO_SHADOWTLS="false"
$env:PROTO_ANYTLS="false"
$env:PROTO_WIREGUARD="false"
$env:PROTO_TAILSCALE="false"
$env:PROTO_SSH="false"
$env:PROTO_TOR="false"
$env:OUTPUT_DIR="include"
& "C:\Program Files\Gitinash.exe" .github/scripts/generate-registry.sh
Write-Host "✅ Generated clean 14-protocol registry files."
```

### 4. 验证防泄露状态 (静态依赖树检查)

执行以下 PowerShell 检查命令，确认多平台依赖树中均仅含 14 个白名单协议：

```powershell
$tags = "with_gvisor,with_quic,with_utls,with_clash_api,badlinkname,tfogo_checklinkname0,with_naive_outbound,with_purego"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$protos = go list -tags=$tags -deps ./cmd/sing-box | Select-String "sing-box/protocol/"
Write-Host "=== Current protocols in build graph ==="
$protos | Select-Object -Unique

# 检查是否泄漏非白名单协议
$forbidden = @("tuic", "tailscale", "wireguard", "snell", "openvpn", "openconnect", "shadowtls", "anytls", "ssh", "tor", "hysteria")
foreach ($f in $forbidden) {
    if ($protos -match $f) {
        Write-Error "❌ LEAK DETECTED: Protocol $f is still in dependency graph!"
    }
}
Write-Host "✅ Dependency graph check passed! Only 14 whitelisted protocols present."
```

### 5. 整理依赖并提交

```bash
go mod tidy
git add .
git commit -m "Merge upstream & Apply 14-protocol smart slim-down"
git push origin testing
```

---

## 🚨 AI Self-Memory Note
在任何一次同步 upstream 的合并中，必须核实以下三个容易复发的“幽灵依赖”：
1. `protocol/hysteria2/outbound.go` 是否恢复了 `import .../protocol/tuic`。
2. `experimental/libbox/native_shell_session.go` 是否丢失了 `with_tailscale` 标签。
3. `include/registry.go` 是否被上游覆盖重新引入了 `snell`, `bridge`, `openconnect`, `openvpn`, `wireguard`, `tailscale` 等。
4. `.github/workflows/build-slim.yml` 是否保留 Windows SFW 桌面客户端构建流程（Node 22, pnpm 10, Rust toolchain, 动态自签名证书与 `build_boxdd` 的 `DEFAULT_BUILD_TAGS_WINDOWS` 瘦身标签同步）。
