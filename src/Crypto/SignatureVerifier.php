<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Crypto;

use Tourze\TLSCryptoAsymmetric\Signature\SignatureVerifier as BaseSignatureVerifier;

/**
 * 签名验证器 - 用于验证证书和CRL的数字签名
 */
class SignatureVerifier
{
    /**
     * @var BaseSignatureVerifier 基础签名验证器
     */
    private BaseSignatureVerifier $baseVerifier;

    /**
     * 构造函数
     */
    public function __construct()
    {
        $this->baseVerifier = new BaseSignatureVerifier();
    }

    /**
     * 验证签名
     *
     * @param string $data      被签名的数据
     * @param string $signature 签名值
     * @param string $publicKey 用于验证的公钥
     * @param string $algorithm 签名算法
     *
     * @return bool 如果签名有效则返回true
     */
    public function verify(string $data, string $signature, string $publicKey, string $algorithm): bool
    {
        return $this->baseVerifier->verify($data, $signature, $publicKey, $algorithm);
    }

    /**
     * 获取支持的算法列表
     *
     * @return array<string> 支持的算法列表
     */
    public function getSupportedAlgorithms(): array
    {
        return $this->baseVerifier->getSupportedAlgorithms();
    }

    /**
     * 检查算法是否受支持
     *
     * @param string $algorithm 要检查的算法
     *
     * @return bool 如果算法受支持则返回true
     */
    public function isAlgorithmSupported(string $algorithm): bool
    {
        return $this->baseVerifier->isAlgorithmSupported($algorithm);
    }
}
