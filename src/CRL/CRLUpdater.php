<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\CRL;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Tourze\TLSCertRevocation\Exception\CRLException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * CRL更新器 - 负责CRL的自动更新和刷新
 */
class CRLUpdater
{
    private LoggerInterface $logger;

    /**
     * @var int 更新前的默认过期阈值（秒）
     */
    private int $refreshThreshold = 3600; // 默认1小时

    /**
     * 构造函数
     *
     * @param CRLParser            $crlParser CRL解析器
     * @param CRLCache             $crlCache  CRL缓存
     * @param LoggerInterface|null $logger    日志记录器
     */
    public function __construct(
        private readonly CRLParser $crlParser,
        private readonly CRLCache $crlCache,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * 设置刷新阈值
     *
     * @param int $seconds 过期前多少秒开始刷新
     */
    public function setRefreshThreshold(int $seconds): void
    {
        $this->refreshThreshold = $seconds;
    }

    /**
     * 从证书获取并更新CRL
     *
     * @param X509Certificate $certificate   证书
     * @param bool            $silentFailure 是否静默失败
     *
     * @return CertificateRevocationList|null 获取到的CRL或null（如果失败）
     */
    public function updateFromCertificate(X509Certificate $certificate, bool $silentFailure = false): ?CertificateRevocationList
    {
        try {
            $issuerDN = $certificate->getIssuerDN();
            if (null === $issuerDN) {
                return null;
            }

            $distributionPoints = $this->getDistributionPoints($certificate);

            if ([] === $distributionPoints) {
                return null;
            }

            $crl = $this->tryUpdateFromDistributionPoints($issuerDN, $distributionPoints);

            if (null === $crl) {
                $crl = $this->getFallbackCRL($issuerDN, $distributionPoints);
            }

            return $crl;
        } catch (\Throwable $e) {
            return $this->handleUpdateError($e, $silentFailure);
        }
    }

    /**
     * 更新特定颁发者的CRL
     *
     * @param string $issuerDN      颁发者DN
     * @param string $url           CRL分发点URL
     * @param bool   $silentFailure 是否静默失败
     *
     * @return bool 是否成功更新
     */
    public function updateCRL(string $issuerDN, string $url, bool $silentFailure = false): bool
    {
        try {
            if (!$this->shouldUpdateCRL($issuerDN)) {
                return true;
            }

            $newCRL = $this->fetchNewCRL($url, $issuerDN);

            if (null === $newCRL) {
                return false;
            }

            if (!$this->shouldAcceptNewCRL($issuerDN, $newCRL)) {
                return false;
            }

            $this->storeCRL($issuerDN, $newCRL);

            return true;
        } catch (\Throwable $e) {
            return $this->handleCRLUpdateError($e, $silentFailure);
        }
    }

    /**
     * 清理过期的CRL
     *
     * @return int 清理的CRL数量
     */
    public function cleanupExpiredCRLs(): int
    {
        $count = $this->crlCache->removeExpired();
        $this->logger->info("已清理 {$count} 个过期CRL");

        return $count;
    }

    /**
     * 获取证书的CRL分发点
     *
     * @param X509Certificate $certificate 证书
     *
     * @return array<string> CRL分发点URL列表
     */
    private function getDistributionPoints(X509Certificate $certificate): array
    {
        $distributionPoints = $this->crlParser->extractCRLDistributionPoints($certificate);

        if ([] === $distributionPoints) {
            $this->logger->warning("证书没有CRL分发点: {$certificate->getSubjectDN()}");
        }

        return $distributionPoints;
    }

    /**
     * 尝试从分发点更新CRL
     *
     * @param string $issuerDN           颁发者DN
     * @param array  $distributionPoints 分发点列表
     *
     * @return CertificateRevocationList|null 更新的CRL或null
     */
    /**
     * @param array<string> $distributionPoints
     */
    private function tryUpdateFromDistributionPoints(string $issuerDN, array $distributionPoints): ?CertificateRevocationList
    {
        foreach ($distributionPoints as $url) {
            try {
                $success = $this->updateCRL($issuerDN, $url, true);
                if ($success) {
                    return $this->crlCache->get($issuerDN);
                }
            } catch (\Throwable $e) {
                $this->logger->warning("从分发点 {$url} 更新CRL失败: " . $e->getMessage());
            }
        }

        return null;
    }

    /**
     * 获取备用CRL（从缓存中）
     *
     * @param string $issuerDN           颁发者DN
     * @param array  $distributionPoints 分发点列表
     *
     * @return CertificateRevocationList 缓存的CRL
     *
     * @throws CRLException 如果没有可用的CRL
     */
    /**
     * @param array<string> $distributionPoints
     */
    private function getFallbackCRL(string $issuerDN, array $distributionPoints): CertificateRevocationList
    {
        $cachedCRL = $this->crlCache->get($issuerDN);

        if (null !== $cachedCRL) {
            $this->logger->info("所有CRL分发点均失败，使用缓存的CRL: {$issuerDN}");

            return $cachedCRL;
        }

        throw new CRLException('无法从任何分发点获取CRL: ' . implode(', ', $distributionPoints));
    }

    /**
     * 处理更新错误
     *
     * @param \Throwable $e             异常
     * @param bool       $silentFailure 是否静默失败
     *
     * @throws \Throwable 如果不是静默失败
     */
    private function handleUpdateError(\Throwable $e, bool $silentFailure): null
    {
        if ($silentFailure) {
            $this->logger->error('更新CRL失败: ' . $e->getMessage());

            return null;
        }

        throw $e;
    }

    /**
     * 检查是否应该更新CRL
     *
     * @param string $issuerDN 颁发者DN
     *
     * @return bool 是否需要更新
     */
    private function shouldUpdateCRL(string $issuerDN): bool
    {
        $currentCRL = $this->crlCache->get($issuerDN);

        if (null !== $currentCRL && !$this->crlCache->isExpiringSoon($issuerDN, $this->refreshThreshold)) {
            $this->logger->debug("CRL无需更新: {$issuerDN}");

            return false;
        }

        return true;
    }

    /**
     * 获取新的CRL
     *
     * @param string $url      CRL URL
     * @param string $issuerDN 预期的颁发者DN
     *
     * @return CertificateRevocationList|null 新的CRL或null
     */
    private function fetchNewCRL(string $url, string $issuerDN): ?CertificateRevocationList
    {
        $this->logger->info("正在从 {$url} 获取CRL");
        $newCRL = $this->crlParser->fetchFromURL($url);

        if ($newCRL->getIssuerDN() !== $issuerDN) {
            $this->logger->warning("获取到的CRL颁发者不匹配: 预期 {$issuerDN}, 实际 {$newCRL->getIssuerDN()}");

            return null;
        }

        return $newCRL;
    }

    /**
     * 检查是否应该接受新的CRL
     *
     * @param string                    $issuerDN 颁发者DN
     * @param CertificateRevocationList $newCRL   新的CRL
     *
     * @return bool 是否接受
     */
    private function shouldAcceptNewCRL(string $issuerDN, CertificateRevocationList $newCRL): bool
    {
        $currentCRL = $this->crlCache->get($issuerDN);

        if (null === $currentCRL) {
            return true;
        }

        return $this->validateCRLUpdate($currentCRL, $newCRL, $issuerDN);
    }

    /**
     * 验证CRL更新
     *
     * @param CertificateRevocationList $currentCRL 当前CRL
     * @param CertificateRevocationList $newCRL     新CRL
     * @param string                    $issuerDN   颁发者DN
     *
     * @return bool 是否有效更新
     */
    private function validateCRLUpdate(CertificateRevocationList $currentCRL, CertificateRevocationList $newCRL, string $issuerDN): bool
    {
        $currentCRLNumber = (int) $currentCRL->getCRLNumber();
        $newCRLNumber = (int) $newCRL->getCRLNumber();

        if ($newCRLNumber < $currentCRLNumber) {
            $this->logger->warning("拒绝更新CRL：新CRL编号 ({$newCRLNumber}) 低于当前编号 ({$currentCRLNumber})");

            return false;
        }

        if ($newCRLNumber === $currentCRLNumber && $newCRL->getThisUpdate() <= $currentCRL->getThisUpdate()) {
            $this->logger->debug("CRL未更新: {$issuerDN}");

            return true; // 不是错误，只是没有更新
        }

        return true;
    }

    /**
     * 存储CRL
     *
     * @param string                    $issuerDN 颁发者DN
     * @param CertificateRevocationList $newCRL   新CRL
     */
    private function storeCRL(string $issuerDN, CertificateRevocationList $newCRL): void
    {
        $this->crlCache->add($issuerDN, $newCRL);
        $this->logger->info("已更新 {$issuerDN} 的CRL");
    }

    /**
     * 处理CRL更新错误
     *
     * @param \Throwable $e             异常
     * @param bool       $silentFailure 是否静默失败
     *
     * @return bool 失败时返回false
     *
     * @throws \Throwable 如果不是静默失败
     */
    private function handleCRLUpdateError(\Throwable $e, bool $silentFailure): bool
    {
        if ($silentFailure) {
            $this->logger->error('更新CRL失败: ' . $e->getMessage());

            return false;
        }

        throw $e;
    }
}
