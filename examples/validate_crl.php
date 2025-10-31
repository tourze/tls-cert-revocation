<?php

/**
 * CRL验证示例脚本
 *
 * 此脚本演示如何使用CRL验证功能检查证书的撤销状态
 */

require __DIR__ . '/../../../vendor/autoload.php';

use Tourze\TLSCertRevocation\Crypto\SignatureVerifier;
use Tourze\TLSCertRevocation\Example\ValidateCRLExample;
use Tourze\TLSCertStore\Repository\X509CertificateLoader;

// 检查命令行参数
if ($argc < 2) {
    echo "用法: php validate_crl.php <证书文件路径> [--force-update]\n";
    exit(1);
}

$certPath = $argv[1];
$forceUpdate = in_array('--force-update', $argv, true);

// 创建证书加载器
$certificateLoader = new X509CertificateLoader();

// 创建签名验证器
$signatureVerifier = new SignatureVerifier();

// 创建验证示例类
$example = new ValidateCRLExample($signatureVerifier);

// 加载证书
try {
    if (!file_exists($certPath)) {
        echo "错误: 证书文件不存在: {$certPath}\n";
        exit(1);
    }

    $pemData = file_get_contents($certPath);
    if (false === $pemData) {
        echo "错误: 无法读取证书文件: {$certPath}\n";
        exit(1);
    }

    $certificate = $certificateLoader->loadFromPEMString($pemData);

    // 验证证书
    $result = $example->validateCertificateRevocation($certificate, $forceUpdate);

    // 显示验证结果
    echo $example->formatValidationResult($result) . "\n\n";

    // 显示CRL统计信息
    echo $example->printCRLStats() . "\n";
} catch (Throwable $e) {
    echo '错误: 证书文件验证失败: ' . $e->getMessage() . "\n";
    exit(1);
}
