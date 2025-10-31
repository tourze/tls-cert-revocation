<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\CRL;

use Tourze\TLSCertRevocation\Exception\CRLException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * 证书撤销列表 - 表示完整的X.509 CRL
 */
class CertificateRevocationList
{
    /**
     * @var array<string, CRLEntry> 撤销条目，按序列号索引
     */
    private array $revokedCertificates = [];

    /**
     * @var X509Certificate|null 颁发者证书
     */
    private ?X509Certificate $issuerCertificate = null;

    /**
     * 构造函数
     *
     * @param string                  $issuerDN           颁发者可分辨名称
     * @param \DateTimeImmutable      $thisUpdate         最后更新时间
     * @param \DateTimeImmutable|null $nextUpdate         下次更新时间
     * @param string                  $crlNumber          CRL序列号
     * @param string|null             $signatureAlgorithm 签名算法
     * @param string|null             $signatureValue     签名值
     * @param string|null             $rawData            原始CRL数据
     */
    public function __construct(
        private readonly string $issuerDN,
        private readonly \DateTimeImmutable $thisUpdate,
        private readonly ?\DateTimeImmutable $nextUpdate,
        private readonly string $crlNumber,
        private readonly ?string $signatureAlgorithm = null,
        private readonly ?string $signatureValue = null,
        private readonly ?string $rawData = null,
    ) {
    }

    /**
     * 添加撤销条目
     *
     * @param CRLEntry $entry 撤销条目
     *
     * @return $this
     */
    public function addRevokedCertificate(CRLEntry $entry): self
    {
        $this->revokedCertificates[$entry->getSerialNumber()] = $entry;

        return $this;
    }

    /**
     * 获取颁发者可分辨名称
     */
    public function getIssuerDN(): string
    {
        return $this->issuerDN;
    }

    /**
     * 获取最后更新时间
     */
    public function getThisUpdate(): \DateTimeImmutable
    {
        return $this->thisUpdate;
    }

    /**
     * 获取下次更新时间
     */
    public function getNextUpdate(): ?\DateTimeImmutable
    {
        return $this->nextUpdate;
    }

    /**
     * 获取所有撤销条目
     *
     * @return array<string, CRLEntry>
     */
    public function getRevokedCertificates(): array
    {
        return $this->revokedCertificates;
    }

    /**
     * 获取CRL序列号
     */
    public function getCRLNumber(): string
    {
        return $this->crlNumber;
    }

    /**
     * 设置颁发者证书
     *
     * @param X509Certificate $certificate 颁发者证书
     */
    public function setIssuerCertificate(X509Certificate $certificate): void
    {
        // 验证证书主题是否与CRL颁发者匹配
        if ($certificate->getSubjectDN() !== $this->issuerDN) {
            throw new CRLException('颁发者证书主题与CRL颁发者不匹配');
        }

        $this->issuerCertificate = $certificate;
    }

    /**
     * 获取颁发者证书
     */
    public function getIssuerCertificate(): ?X509Certificate
    {
        return $this->issuerCertificate;
    }

    /**
     * 获取签名算法
     */
    public function getSignatureAlgorithm(): ?string
    {
        return $this->signatureAlgorithm;
    }

    /**
     * 获取签名值
     */
    public function getSignatureValue(): ?string
    {
        return $this->signatureValue;
    }

    /**
     * 获取原始CRL数据
     */
    public function getRawData(): ?string
    {
        return $this->rawData;
    }

    /**
     * 检查CRL是否已过期
     *
     * @return bool 如果已过期则返回true
     */
    public function isExpired(): bool
    {
        if (null === $this->nextUpdate) {
            return false; // 没有设置nextUpdate，无法确定是否过期
        }

        $now = new \DateTimeImmutable();

        return $now > $this->nextUpdate;
    }

    /**
     * 检查证书是否被撤销
     *
     * @param string $serialNumber 证书序列号
     *
     * @return bool 如果证书已被撤销则返回true
     */
    public function isRevoked(string $serialNumber): bool
    {
        return isset($this->revokedCertificates[$serialNumber]);
    }

    /**
     * 获取撤销证书条目
     *
     * @param string $serialNumber 证书序列号
     *
     * @return CRLEntry|null 如果找到则返回撤销条目，否则返回null
     */
    public function getRevokedCertificate(string $serialNumber): ?CRLEntry
    {
        return $this->revokedCertificates[$serialNumber] ?? null;
    }
}
