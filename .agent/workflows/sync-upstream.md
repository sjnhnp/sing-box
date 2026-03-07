---
description: Sync with upstream sing-box while intelligently preserving custom slim-down modifications.
---

# Smart Sync Upstream Workflow

此 workflow 用于同步上游 SagerNet/sing-box 的最新代码，采用**智能合并策略**：

1. **保留上游变更**：默认接受上游的所有新代码（包括新协议、Bug修复）。
2. **智能精简**：使用脚本自动再次移除（注释掉）你不需要的协议。
3. **保留配置**：CI 配置文件和文档直接保留你的版本。

## 执行步骤

### 1. 备份关键文件 (作为安全网)

// turbo

```bash
$backupDir = Join-Path $env:TEMP "sing-box-backup"
if (Test-Path $backupDir) { Remove-Item -Recurse -Force $backupDir }
New-Item -ItemType Directory -Force -Path "$backupDir\.github\workflows" | Out-Null
Copy-Item ".github\workflows\build-slim.yml" -Destination "$backupDir\.github\workflows\build-slim.yml"
Copy-Item ".github\workflows\sync-upstream-preserve.yml" -Destination "$backupDir\.github\workflows\sync-upstream-preserve.yml"
Copy-Item "README.md" -Destination "$backupDir\README.md"
# 备份代码文件以防万一
Copy-Item "include\registry.go" -Destination "$backupDir\registry.go"
Copy-Item "include\quic.go" -Destination "$backupDir\quic.go"
Copy-Item "include\quic_stub.go" -Destination "$backupDir\quic_stub.go"

Write-Host "✅ Backup created at $backupDir"
```

### 2. 同步上游代码

使用 `-X theirs` 策略合并，这意味着如果发生冲突，我们将**优先使用上游的最新代码**。这会自动把我们在 `registry.go` 等文件中注释掉的代码恢复（取消注释）。别担心，下一步我们会再次把它们“修剪”掉。

// turbo

```bash
git remote add upstream https://github.com/SagerNet/sing-box.git 2>$null
git fetch upstream --tags
git merge upstream/testing -X theirs -m "Merge upstream testing (Smart Sync)"
```

### 3. 恢复 CI 配置和文档

对于 `.github` 目录和 `README.md`，我们完全不关心上游的变化，直接强制恢复我们的版本。

// turbo

```bash
$backupDir = Join-Path $env:TEMP "sing-box-backup"
Copy-Item "$backupDir\.github\workflows\build-slim.yml" -Destination ".github\workflows\build-slim.yml" -Force
Copy-Item "$backupDir\.github\workflows\sync-upstream-preserve.yml" -Destination ".github\workflows\sync-upstream-preserve.yml" -Force
Copy-Item "$backupDir\README.md" -Destination "README.md" -Force
# quic_stub.go 比较特殊，它的修改是为了配合精简，上游通常不会改这个文件的核心逻辑，直接恢复最安全
Copy-Item "$backupDir\quic_stub.go" -Destination "include\quic_stub.go" -Force
```

### 4. 执行智能精简脚本

此脚本会扫描代码文件，将不需要的协议再次注释掉。这样既保留了上游的新功能，又维持了你的精简配置。

// turbo

```powershell
function Slim-Down-File {
    param ($Path, $Imports, $Registers)
    
    Write-Host "Processing $Path..."
    $content = Get-Content $Path -Raw

    # 1. Comment out Imports
    foreach ($imp in $Imports) {
        # 匹配 import 行，但忽略已经被注释的行
        # Regex: 必须匹配双引号内的包名，且行首不能已经有 // Removed
        $pattern = '(?m)^(?!\s*// Removed:)\s*"' + [regex]::Escape($imp) + '"'
        $replacement = '// Removed: ' + $imp + ' - not used'
        
        # 使用 RegexReplace 可能会破坏格式，这里我们用简单的行处理或者精细正则
        # 为了稳健，我们用正则替换整行
        $content = $content -replace $pattern, (' ' + $replacement)
    }

    # 2. Comment out Registers
    foreach ($reg in $Registers) {
        # Regex: 匹配 "package.Register...(registry)"
        $pattern = '(?m)^(?!\s*// Removed:)\s*' + [regex]::Escape($reg) + '\('
        $replacement = '// Removed: ' + $reg + '('
        $content = $content -replace $pattern, (' ' + $replacement)
    }

    Set-Content -Path $Path -Value $content -NoNewline
}

# --- 处理 include/registry.go ---
$registryImports = @(
    "github.com/sagernet/sing-box/protocol/anytls",
    "github.com/sagernet/sing-box/protocol/shadowtls",
    "github.com/sagernet/sing-box/protocol/ssh",
    "github.com/sagernet/sing-box/protocol/tor"
)
$registryRegs = @(
    "shadowtls.RegisterInbound",
    "anytls.RegisterInbound",
    "tor.RegisterOutbound",
    "ssh.RegisterOutbound",
    "shadowtls.RegisterOutbound",
    "anytls.RegisterOutbound"
)
Slim-Down-File -Path "include/registry.go" -Imports $registryImports -Registers $registryRegs

# --- 处理 include/quic.go ---
$quicImports = @(
    "github.com/sagernet/sing-box/protocol/hysteria", # v1
    "github.com/sagernet/sing-box/protocol/tuic"
)
$quicRegs = @(
    "hysteria.RegisterInbound",
    "tuic.RegisterInbound",
    "hysteria.RegisterOutbound",
    "tuic.RegisterOutbound"
)
Slim-Down-File -Path "include/quic.go" -Imports $quicImports -Registers $quicRegs

Write-Host "✅ Smart slim-down complete."
```

### 5. 检查差异并提交

// turbo

```bash
echo "=== 自动处理后的差异 ==="
git diff
echo ""
echo "即将提交..."
```

### 6. 提交更改

```bash
git add include/registry.go include/quic.go include/quic_stub.go
git add .github/workflows/build-slim.yml .github/workflows/sync-upstream-preserve.yml
git add README.md
git commit -m "Merge upstream & Apply smart slim-down"
git push origin testing
```
