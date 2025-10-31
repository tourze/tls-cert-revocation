<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\OCSP;

use Tourze\TLSCertRevocation\Exception\OCSPException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * OCSP请求类 - 用于构建OCSP请求
 */
class OCSPRequest
{
    /**
     * @var string|null 编码的请求数据
     */
    private ?string $encodedRequest = null;

    /**
     * 构造函数
     *
     * @param string      $serialNumber   证书序列号
     * @param string      $issuerNameHash 颁发者名称散列值
     * @param string      $issuerKeyHash  颁发者公钥散列值
     * @param string      $hashAlgorithm  散列算法
     * @param string|null $nonce          随机数
     */
    public function __construct(
        private readonly string $serialNumber,
        private readonly string $issuerNameHash,
        private readonly string $issuerKeyHash,
        private readonly string $hashAlgorithm = 'sha1',
        private readonly ?string $nonce = null,
    ) {
    }

    /**
     * 从证书创建OCSP请求
     *
     * @param X509Certificate $certificate       要检查的证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @param string          $hashAlgorithm     散列算法
     * @param bool            $includeNonce      是否包含随机数
     *
     * @throws OCSPException 如果创建请求失败
     */
    public static function fromCertificate(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        string $hashAlgorithm = 'sha1',
        bool $includeNonce = true,
    ): self {
        try {
            $serialNumber = $certificate->getSerialNumber();
            if (null === $serialNumber) {
                throw new OCSPException('无法获取证书序列号');
            }

            $issuerNameHash = self::calculateIssuerNameHash($issuerCertificate, $hashAlgorithm);
            $issuerKeyHash = self::calculateIssuerKeyHash($issuerCertificate, $hashAlgorithm);
            $nonce = $includeNonce ? bin2hex(random_bytes(16)) : null;

            return new self(
                $serialNumber,
                bin2hex($issuerNameHash),
                bin2hex($issuerKeyHash),
                $hashAlgorithm,
                $nonce
            );
        } catch (OCSPException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new OCSPException('创建OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 构建DER编码的OCSP请求
     *
     * @return string DER编码的OCSP请求
     *
     * @throws OCSPException 如果构建请求失败
     */
    public function encode(): string
    {
        if (null !== $this->encodedRequest) {
            return $this->encodedRequest;
        }

        try {
            // 注意：这里简化了实现，实际应该使用ASN.1库构建OCSP请求
            // RFC 6960 定义了OCSP请求的ASN.1结构

            // 这是一个基本的骨架实现
            // 在实际项目中，应该使用ASN.1库如phpseclib来构建请求

            // 这里调用内部方法实现详细的编码
            $this->encodedRequest = $this->_encodeRequest();

            return $this->encodedRequest;
        } catch (\Throwable $e) {
            throw new OCSPException('编码OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 内部编码请求方法
     *
     * @return string 编码后的请求
     */
    protected function _encodeRequest(): string
    {
        // TODO: 实现完整的ASN.1编码
        // 这里简化实现，返回一个占位符值
        return 'encoded-ocsp-request-placeholder';
    }

    /**
     * 编码OCSP请求用于HTTP传输
     *
     * @return string Base64编码的请求数据
     *
     * @throws OCSPException 如果编码失败
     */
    public function encodeForHTTP(): string
    {
        $rawData = $this->encode();

        return base64_encode($rawData);
    }

    /**
     * 获取请求的URL
     *
     * @param string $baseUrl OCSP响应者基本URL
     *
     * @return string 完整请求URL
     *
     * @throws OCSPException 如果编码失败
     */
    public function getRequestURL(string $baseUrl): string
    {
        $encodedRequest = $this->encodeForHTTP();

        // 确保URL以斜杠结尾
        if ('/' !== substr($baseUrl, -1)) {
            $baseUrl .= '/';
        }

        return $baseUrl . $encodedRequest;
    }

    /**
     * 使用OpenSSL生成OCSP请求
     *
     * @param X509Certificate $certificate       要检查的证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     *
     * @throws OCSPException 如果生成失败
     */
    public static function generateWithOpenSSL(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
    ): self {
        try {
            // OpenSSL功能的简化实现
            // 在实际项目中，应该使用OpenSSL扩展函数生成请求

            // 这里调用fromCertificate作为兜底方案
            return self::fromCertificate($certificate, $issuerCertificate);
        } catch (OCSPException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new OCSPException('使用OpenSSL生成OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 获取证书序列号
     */
    public function getSerialNumber(): string
    {
        return $this->serialNumber;
    }

    /**
     * 获取颁发者名称散列值
     */
    public function getIssuerNameHash(): string
    {
        return $this->issuerNameHash;
    }

    /**
     * 获取颁发者公钥散列值
     */
    public function getIssuerKeyHash(): string
    {
        return $this->issuerKeyHash;
    }

    /**
     * 获取散列算法
     */
    public function getHashAlgorithm(): string
    {
        return $this->hashAlgorithm;
    }

    /**
     * 获取随机数
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * 计算颁发者名称散列
     *
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @param string          $hashAlgorithm     散列算法
     *
     * @return string 散列值
     *
     * @throws OCSPException 如果计算失败
     */
    private static function calculateIssuerNameHash(X509Certificate $issuerCertificate, string $hashAlgorithm): string
    {
        $issuerName = self::getIssuerNameDER($issuerCertificate);

        return hash($hashAlgorithm, $issuerName, true);
    }

    /**
     * 计算颁发者公钥散列
     *
     * @param X509Certificate $issuerCertificate 颁发者证书
     * @param string          $hashAlgorithm     散列算法
     *
     * @return string 散列值
     *
     * @throws OCSPException 如果计算失败
     */
    private static function calculateIssuerKeyHash(X509Certificate $issuerCertificate, string $hashAlgorithm): string
    {
        $issuerPublicKey = self::getIssuerPublicKeyDER($issuerCertificate);

        return hash($hashAlgorithm, $issuerPublicKey, true);
    }

    /**
     * 获取颁发者名称的DER编码
     *
     * @param X509Certificate $issuerCertificate 颁发者证书
     *
     * @return string DER编码的颁发者名称
     *
     * @throws OCSPException 如果获取失败
     */
    private static function getIssuerNameDER(X509Certificate $issuerCertificate): string
    {
        $issuerName = $issuerCertificate->getSubjectDNDER();

        if ('' !== $issuerName) {
            return $issuerName;
        }

        // 尝试替代方法获取DN
        $issuerName = $issuerCertificate->getSubjectDN(true);
        if (null !== $issuerName && '' !== $issuerName) {
            return $issuerName;
        }

        // 使用备用方法生成
        $subject = $issuerCertificate->getSubjectDN(false);
        if (null === $subject || '' === $subject) {
            throw new OCSPException('无法获取颁发者主题DN');
        }

        // 假设此处有更直接的方式将字符串转为DER，以下是占位
        return "CN={$subject}";
    }

    /**
     * 获取颁发者公钥的DER编码
     *
     * @param X509Certificate $issuerCertificate 颁发者证书
     *
     * @return string DER编码的颁发者公钥
     *
     * @throws OCSPException 如果获取失败
     */
    private static function getIssuerPublicKeyDER(X509Certificate $issuerCertificate): string
    {
        $issuerPublicKey = $issuerCertificate->getPublicKeyDER();

        if (null !== $issuerPublicKey) {
            return $issuerPublicKey;
        }

        // 尝试替代方法获取公钥
        $issuerPublicKey = $issuerCertificate->getPublicKey();
        if (null === $issuerPublicKey || '' === $issuerPublicKey) {
            throw new OCSPException('无法获取颁发者公钥DER编码');
        }

        return $issuerPublicKey;
    }
}
