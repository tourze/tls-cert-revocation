# TLS 证书撤销检查

[![PHP](https://img.shields.io/badge/php-%5E8.1-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](#)

[English](README.md) | [中文](README.zh-CN.md)

一个用于处理 TLS 证书撤销检查的 PHP 库，全面支持 CRL（证书撤销列表）和 OCSP（在线证书状态协议）验证机制。

## 目录

- [安装](#安装)
- [系统要求](#系统要求)
- [特性](#特性)
- [快速开始](#快速开始)
- [撤销策略](#撤销策略)
- [高级用法](#高级用法)
- [示例](#示例)
- [测试](#测试)
- [贡献](#贡献)
- [许可证](#许可证)
- [相关包](#相关包)

## 安装

```bash
composer require tourze/tls-cert-revocation
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- curl 扩展 (用于 OCSP 请求)

## 特性

- **CRL (证书撤销列表) 处理**
  - CRL 解析和验证
  - CRL 缓存以提高性能
  - 签名验证
  - 自动 CRL 更新
  
- **OCSP (在线证书状态协议) 支持**
  - OCSP 请求/响应处理
  - OCSP 装订支持
  - 实时证书状态检查
  
- **灵活的撤销策略**
  - 多种回退策略
  - 可配置的失败处理
  - 支持网络不稳定环境
  
- **缓存和性能**
  - 智能撤销信息缓存
  - 可配置的缓存过期时间
  - 网络故障恢复能力

## 快速开始

### 基本撤销检查

```php
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;
use Tourze\TLSX509Core\Certificate\X509Certificate;

// 加载证书
$certificate = X509Certificate::fromPEM(file_get_contents('cert.pem'));
$issuer = X509Certificate::fromPEM(file_get_contents('issuer.pem'));

// 创建检查器，使用 OCSP 优先策略
$checker = new RevocationChecker(RevocationPolicy::OCSP_PREFERRED);

// 检查证书是否被撤销
$isValid = $checker->check($certificate, $issuer);

if ($isValid) {
    echo "证书有效，未被撤销\n";
} else {
    echo "证书已撤销或状态未知\n";
}

// 获取详细的检查结果
$status = $checker->getLastCheckStatus();
print_r($status);
```

### 仅 CRL 验证

```php
use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// 创建 CRL 验证器
$crlValidator = new CRLValidator();

// 创建检查器，使用仅 CRL 策略
$checker = new RevocationChecker(
    RevocationPolicy::CRL_ONLY,
    null,
    $crlValidator
);

$isValid = $checker->check($certificate, $issuer);
```

### 仅 OCSP 验证

```php
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// 创建 OCSP 客户端
$ocspClient = new OCSPClient();

// 创建检查器，使用仅 OCSP 策略
$checker = new RevocationChecker(
    RevocationPolicy::OCSP_ONLY,
    $ocspClient
);

$isValid = $checker->check($certificate, $issuer);
```

## 撤销策略

库支持多种撤销检查策略：

| 策略 | 描述 |
|------|------|
| `SOFT_FAIL` | 即使撤销检查失败（网络错误）也继续验证 |
| `HARD_FAIL` | 将任何撤销检查失败视为无效证书 |
| `CRL_ONLY` | 仅使用 CRL 进行撤销检查 |
| `OCSP_ONLY` | 仅使用 OCSP 进行撤销检查 |
| `OCSP_PREFERRED` | 先尝试 OCSP，如果 OCSP 失败则回退到 CRL |
| `CRL_PREFERRED` | 先尝试 CRL，如果 CRL 失败则回退到 OCSP |
| `DISABLED` | 跳过所有撤销检查 |

## 高级用法

### 自定义 CRL 缓存

```php
use Tourze\TLSCertRevocation\CRL\CRLCache;
use Tourze\TLSCertRevocation\CRL\CRLValidator;

// 创建缓存，自定义 TTL（1小时）
$cache = new CRLCache(3600);

// 创建验证器，使用自定义缓存
$validator = new CRLValidator($cache);
```

### 处理网络故障

```php
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// 对于不稳定的网络环境使用软失败
$checker = new RevocationChecker(RevocationPolicy::SOFT_FAIL);

$isValid = $checker->check($certificate, $issuer);
$status = $checker->getLastCheckStatus();

// 检查尝试了哪些方法
foreach ($status['methods_tried'] as $method) {
    echo "尝试方法: $method\n";
}

// 检查特定错误
if (isset($status['ocsp_error'])) {
    echo "OCSP 错误: " . $status['ocsp_error'] . "\n";
}
if (isset($status['crl_error'])) {
    echo "CRL 错误: " . $status['crl_error'] . "\n";
}
```

### 手动 CRL 处理

```php
use Tourze\TLSCertRevocation\CRL\CRLParser;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;

// 从 DER 数据解析 CRL
$crlData = file_get_contents('certificate.crl');
$parser = new CRLParser();
$crl = $parser->parse($crlData);

// 检查证书是否在 CRL 中
$serialNumber = $certificate->getSerialNumber();
if ($crl->isRevoked($serialNumber)) {
    $entry = $crl->getRevokedCertificate($serialNumber);
    echo "证书撤销日期: " . $entry->getRevocationDate()->format('Y-m-d H:i:s') . "\n";
    echo "撤销原因: " . $entry->getReasonCode() . "\n";
}
```

### 自定义 OCSP 请求

```php
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSCertRevocation\OCSP\OCSPRequest;

$client = new OCSPClient();

// 创建自定义 OCSP 请求
$request = new OCSPRequest($certificate, $issuer);

// 发送请求到特定的 OCSP 响应器
$response = $client->sendRequest($request, 'http://ocsp.example.com');

// 检查响应
switch ($response->getCertStatus()) {
    case 0: // 良好
        echo "证书有效\n";
        break;
    case 1: // 已撤销
        echo "证书已被撤销\n";
        break;
    case 2: // 未知
        echo "证书状态未知\n";
        break;
}
```

## 示例

查看 `examples/` 目录中的完整工作示例：

- `validate_crl.php` - 完整的 CRL 验证示例

## 测试

```bash
# 运行所有测试
./vendor/bin/phpunit packages/tls-cert-revocation/tests

# 运行特定测试
./vendor/bin/phpunit packages/tls-cert-revocation/tests/RevocationCheckerTest.php
```

## 贡献

1. Fork 仓库
2. 创建功能分支
3. 进行更改
4. 为新功能添加测试
5. 运行测试套件
6. 提交 pull request

## 许可证

MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 相关包

- `tourze/tls-common` - 通用 TLS 工具
- `tourze/tls-crypto-asymmetric` - 非对称加密
- `tourze/tls-x509-core` - X.509 证书处理
- `tourze/tls-x509-validation` - X.509 验证工具