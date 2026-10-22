# Moat WAF 安全自动化

该目录和 `security_automation/` 构成 Moat WAF 的外部安全控制面。WAF 运行时不访问
NVD、OSV、CISA 等外部服务，也不新增运行时依赖。

## 自动化内容

- 每天北京时间约 02:30 构建镜像并生成 CycloneDX SBOM。
- 使用 OSV 匹配 SBOM 中的开源组件漏洞。
- 使用 CISA KEV 标记已知在野利用漏洞。
- 配置 `NVD_API_KEY` 后，使用 NVD 补充 CVSS 和引用信息。
- 将结果上传为 GitHub Actions 制品，并更新
  `[security-intel] Vulnerability backlog` 滚动工单。
- 每周检查 Docker 基础镜像和 GitHub Actions 依赖更新。
- 版本标签 `v*` 触发确定性规则包构建和 Sigstore 签名发布。

## 手工执行

生成 SBOM：

```bash
docker build -t moat-waf:security-scan .
trivy image \
  --format cyclonedx \
  --output security-artifacts/sbom.cdx.json \
  moat-waf:security-scan
```

执行漏洞匹配：

```bash
python3 -m security_automation.cli scan \
  --sbom security-artifacts/sbom.cdx.json \
  --output-dir security-artifacts/intel
```

可选启用 NVD：

```bash
export NVD_API_KEY="..."
python3 -m security_automation.cli scan \
  --sbom security-artifacts/sbom.cdx.json \
  --output-dir security-artifacts/intel
```

输出：

- `vulnerabilities.json`：完整机器可读结果。
- `report.md`：按 KEV、严重级别排序的详细报告。
- `issue.md`：滚动工单摘要。

## 规则包

构建：

```bash
python3 scripts/build_rule_pack.py \
  --rules-dir rules \
  --output-dir dist \
  --version v1.0.0
```

产物包含规则、`manifest.json`、SHA-256 校验文件。正式版本由
`.github/workflows/rule-pack-release.yml` 使用 Sigstore keyless signing 签名。

验证：

```bash
shasum -a 256 -c dist/moat-waf-rules-v1.0.0.tar.gz.sha256
cosign verify-blob \
  --certificate dist/moat-waf-rules-v1.0.0.tar.gz.pem \
  --signature dist/moat-waf-rules-v1.0.0.tar.gz.sig \
  --certificate-identity-regexp 'https://github.com/ligg/moatwaf/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  dist/moat-waf-rules-v1.0.0.tar.gz
```

## 发布与回滚

1. 漏洞扫描生成滚动工单或代码扫描告警。
2. 依赖补丁和次版本更新在检查通过后由 Dependabot 自动合并。
3. 主版本升级、安全规则变更和基础镜像大版本升级需要人工确认。
4. 发布标签后生成新的签名规则包。
5. 发现规则误报或回归时，重新部署上一版本的规则目录和 `.version` 文件。

## 安全边界

- 自动扫描结果不会直接写入或发布 WAF 规则。
- 规则包必须经过测试和版本标签才能发布。
- 自动合并只应用于官方 Dependabot 的补丁和次版本更新。
- GitHub 分支保护应要求 `security-intel` 和现有 Docker 测试通过。

