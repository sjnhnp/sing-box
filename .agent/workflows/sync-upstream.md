---
description: 同步上游 sing-box 代码，保留自定义精简协议配置
---

# Sync Upstream Workflow

此 workflow 用于同步上游 SagerNet/sing-box 的最新代码，同时保留你的自定义修改。

## 自定义文件列表

以下文件包含你的自定义修改，同步时必须保留：

**协议精简文件：**
- `include/registry.go` - 移除不需要的协议注册
- `include/quic.go` - 只保留 hysteria2
- `include/quic_stub.go` - 对应的 stub 文件

**自定义工作流：**
- `.github/workflows/build-slim.yml` - 多平台精简构建
- `.github/workflows/sync-upstream-preserve.yml` - GitHub Actions 同步工作流

## 执行步骤

### 1. 备份自定义文件

// turbo
```bash
mkdir -p /tmp/sing-box-backup
cp include/registry.go /tmp/sing-box-backup/
cp include/quic.go /tmp/sing-box-backup/
cp include/quic_stub.go /tmp/sing-box-backup/
cp .github/workflows/build-slim.yml /tmp/sing-box-backup/
cp .github/workflows/sync-upstream-preserve.yml /tmp/sing-box-backup/
echo "✅ 自定义文件已备份到 /tmp/sing-box-backup/"
```

### 2. 添加上游远程仓库

// turbo
```bash
git remote add upstream https://github.com/SagerNet/sing-box.git 2>/dev/null || echo "upstream 已存在"
git fetch upstream --tags
```

### 3. 查看同步状态

// turbo
```bash
echo "=== 当前分支状态 ==="
git branch -v
echo ""
echo "=== 与上游的差异 ==="
BEHIND=$(git rev-list --count HEAD..upstream/dev-next)
AHEAD=$(git rev-list --count upstream/dev-next..HEAD)
echo "落后上游: ${BEHIND} 个提交"
echo "领先上游: ${AHEAD} 个提交 (你的自定义)"
echo ""
echo "=== 上游最新提交 (前10个) ==="
git log --oneline upstream/dev-next -10
```

### 4. 检查自定义文件是否有上游更新

// turbo
```bash
echo "=== 检查自定义文件的上游变更 ==="
for file in include/registry.go include/quic.go include/quic_stub.go; do
  if ! git diff --quiet HEAD..upstream/dev-next -- "$file" 2>/dev/null; then
    echo "⚠️  $file 在上游有变更，需要注意"
    echo "    上游变更摘要:"
    git diff --stat HEAD..upstream/dev-next -- "$file"
  else
    echo "✅ $file 上游无变更"
  fi
done
```

### 5. 合并上游代码

使用 `theirs` 策略合并，优先采用上游版本解决冲突：

```bash
git merge upstream/dev-next -X theirs -m "Merge upstream dev-next"
```

### 6. 恢复自定义文件

// turbo
```bash
cp /tmp/sing-box-backup/registry.go include/registry.go
cp /tmp/sing-box-backup/quic.go include/quic.go
cp /tmp/sing-box-backup/quic_stub.go include/quic_stub.go
cp /tmp/sing-box-backup/build-slim.yml .github/workflows/build-slim.yml
cp /tmp/sing-box-backup/sync-upstream-preserve.yml .github/workflows/sync-upstream-preserve.yml
echo "✅ 自定义文件已恢复"
```

### 7. 检查是否需要更新自定义文件

如果上游对 `include/registry.go` 等文件有重要更新（如新增必要的 import），需要手动合并：

```bash
# 查看上游的 registry.go 有哪些变化
git diff upstream/dev-next -- include/registry.go

# 如果有需要的新 import 或代码，手动编辑 include/registry.go 添加
```

### 8. 提交恢复的自定义文件

```bash
git add include/registry.go include/quic.go include/quic_stub.go
git add .github/workflows/build-slim.yml .github/workflows/sync-upstream-preserve.yml
git commit -m "Restore custom slim protocol modifications after upstream sync"
```

### 9. 推送到远程仓库

```bash
git push origin dev-next
```

## 如果出现冲突

如果合并过程中出现无法自动解决的冲突：

1. 查看冲突文件：`git status`
2. 对于非自定义文件，采用上游版本：`git checkout --theirs <file>`
3. 对于自定义文件，使用备份版本恢复
4. 标记冲突已解决：`git add <file>`
5. 完成合并：`git commit`

## 验证同步结果

// turbo
```bash
echo "=== 同步后状态 ==="
git log --oneline -5
echo ""
echo "=== 验证自定义文件 ==="
head -5 include/registry.go
echo "..."
grep -c "Removed:" include/registry.go && echo "✅ 自定义注释存在"
```
