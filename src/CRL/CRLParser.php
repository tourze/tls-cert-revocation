<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\CRL;

use Tourze\TLSCertRevocation\Exception\CRLException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * CRL解析器 - 解析X.509证书撤销列表
 */
class CRLParser
{
    private OpenSSLCommandHandler $commandHandler;

    /**
     * 构造函数
     */
    public function __construct(?OpenSSLCommandHandler $commandHandler = null)
    {
        $this->commandHandler = $commandHandler ?? new OpenSSLCommandHandler();
    }

    /**
     * 解析PEM格式的CRL
     *
     * @param string $pemData PEM格式的CRL数据
     *
     * @return CertificateRevocationList 解析后的CRL
     *
     * @throws CRLException 如果解析失败
     */
    public function parsePEM(string $pemData): CertificateRevocationList
    {
        // 提取PEM数据
        if (1 !== preg_match('/-+BEGIN X509 CRL-+(.+?)-+END X509 CRL-+/s', $pemData, $matches)) {
            throw CRLException::parseError('无效的PEM格式');
        }

        // 解码Base64数据
        $derData = base64_decode(trim($matches[1]), true);
        if (false === $derData) {
            throw CRLException::parseError('无效的Base64编码');
        }

        return $this->parseDER($derData);
    }

    /**
     * 解析DER格式的CRL
     *
     * @param string $derData DER格式的CRL数据
     *
     * @return CertificateRevocationList 解析后的CRL
     *
     * @throws CRLException 如果解析失败
     */
    public function parseDER(string $derData): CertificateRevocationList
    {
        try {
            $crlInfo = $this->commandHandler->parseFromDER($derData);
            $crl = $this->createCRLFromInfo($crlInfo, $derData);
            $this->processRevokedCertificates($crl, $crlInfo);

            return $crl;
        } catch (CRLException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw CRLException::parseError('解析DER数据失败: ' . $e->getMessage());
        }
    }

    /**
     * 处理撤销证书列表
     *
     * @param CertificateRevocationList $crl CRL对象
     * @param array<string, mixed> $crlInfo CRL信息
     */
    private function processRevokedCertificates(CertificateRevocationList $crl, array $crlInfo): void
    {
        $revokedCerts = $crlInfo['revoked'] ?? [];
        if (is_array($revokedCerts)) {
            $validRevokedCerts = $this->validateRevokedCertificates($revokedCerts);
            $this->addRevokedCertificatesToCRL($crl, $validRevokedCerts);
        }
    }

    /**
     * 验证撤销证书数据结构
     *
     * @param array<mixed> $revokedCerts 撤销证书数据
     * @return array<int, array<string, mixed>> 验证后的撤销证书数据
     */
    private function validateRevokedCertificates(array $revokedCerts): array
    {
        $validRevokedCerts = [];
        foreach ($revokedCerts as $index => $cert) {
            if (is_array($cert) && is_int($index)) {
                $validCert = $this->validateCertificateEntry($cert);
                $validRevokedCerts[$index] = $validCert;
            }
        }

        return $validRevokedCerts;
    }

    /**
     * 验证单个证书条目
     *
     * @param array<mixed> $cert 证书条目数据
     * @return array<string, mixed> 验证后的证书数据
     */
    private function validateCertificateEntry(array $cert): array
    {
        $validCert = [];
        foreach ($cert as $key => $value) {
            if (is_string($key)) {
                $validCert[$key] = $value;
            }
        }

        return $validCert;
    }

    /**
     * 从CRL信息创建CRL对象
     *
     * @param array<string, mixed> $crlInfo CRL信息
     * @param string               $derData DER数据
     *
     * @return CertificateRevocationList CRL对象
     */
    private function createCRLFromInfo(array $crlInfo, string $derData): CertificateRevocationList
    {
        $issuerDNValue = $crlInfo['issuer'] ?? '';
        $issuerDN = is_string($issuerDNValue) ? $issuerDNValue : '';

        $lastUpdateStr = $crlInfo['lastUpdate'] ?? null;
        $thisUpdate = is_string($lastUpdateStr) ? new \DateTimeImmutable($lastUpdateStr) : new \DateTimeImmutable();

        $nextUpdateStr = $crlInfo['nextUpdate'] ?? null;
        $nextUpdate = is_string($nextUpdateStr) ? new \DateTimeImmutable($nextUpdateStr) : null;

        $crlNumberValue = $crlInfo['crlNumber'] ?? '0';
        $crlNumber = is_string($crlNumberValue) ? $crlNumberValue : '0';
        $signatureAlgorithm = isset($crlInfo['signatureAlgorithm']) && is_string($crlInfo['signatureAlgorithm']) ? $crlInfo['signatureAlgorithm'] : null;

        return new CertificateRevocationList(
            $issuerDN,
            $thisUpdate,
            $nextUpdate,
            $crlNumber,
            $signatureAlgorithm,
            null, // 签名值需要另外提取
            $derData
        );
    }

    /**
     * 添加撤销证书到CRL
     *
     * @param CertificateRevocationList        $crl          CRL对象
     * @param array<int, array<string, mixed>> $revokedCerts 撤销证书信息
     */
    private function addRevokedCertificatesToCRL(CertificateRevocationList $crl, array $revokedCerts): void
    {
        foreach ($revokedCerts as $cert) {
            $entry = $this->createCRLEntry($cert);
            $crl->addRevokedCertificate($entry);
        }
    }

    /**
     * 创建CRL条目
     *
     * @param array<string, mixed> $cert 证书信息
     *
     * @return CRLEntry CRL条目
     */
    private function createCRLEntry(array $cert): CRLEntry
    {
        $serialNumberValue = $cert['serialNumber'] ?? '';
        $serialNumber = is_string($serialNumberValue) ? $serialNumberValue : '';

        $revocationDateStr = $cert['revocationDate'] ?? null;
        $revocationDate = is_string($revocationDateStr) ? new \DateTimeImmutable($revocationDateStr) : new \DateTimeImmutable();

        $reasonCodeValue = $cert['reasonCode'] ?? null;
        $reasonCode = $this->parseReasonCode(is_string($reasonCodeValue) ? $reasonCodeValue : null);
        $invalidityDate = null;

        return new CRLEntry($serialNumber, $revocationDate, $reasonCode, $invalidityDate);
    }

    /**
     * 解析撤销原因代码
     *
     * @param string|null $reasonCodeText 原因代码文本
     *
     * @return int|null 原因代码数字
     */
    private function parseReasonCode(?string $reasonCodeText): ?int
    {
        if (null === $reasonCodeText) {
            return null;
        }

        $reasonMap = [
            'Unspecified' => 0,
            'Key Compromise' => 1,
            'CA Compromise' => 2,
            'Affiliation Changed' => 3,
            'Superseded' => 4,
            'Cessation Of Operation' => 5,
            'Certificate Hold' => 6,
            'Remove From CRL' => 8,
            'Privilege Withdrawn' => 9,
            'AA Compromise' => 10,
        ];

        foreach ($reasonMap as $text => $code) {
            if (false !== strpos($reasonCodeText, $text)) {
                return $code;
            }
        }

        return null;
    }

    /**
     * 从URL获取并解析CRL
     *
     * @param string $url CRL的URL
     *
     * @return CertificateRevocationList 解析后的CRL
     *
     * @throws CRLException 如果获取或解析失败
     */
    public function fetchFromURL(string $url): CertificateRevocationList
    {
        try {
            // 获取CRL数据
            $crlData = $this->fetchData($url);

            // 根据内容类型选择解析方法
            if (false !== strpos($crlData, '-----BEGIN')) {
                return $this->parsePEM($crlData);
            }

            return $this->parseDER($crlData);
        } catch (CRLException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw CRLException::notFound($url . ': ' . $e->getMessage());
        }
    }

    /**
     * 从URL获取数据
     *
     * @param string $url 要获取数据的URL
     *
     * @return string 获取到的数据
     *
     * @throws \Exception 如果获取失败
     */
    protected function fetchData(string $url): string
    {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 30,
                'header' => 'User-Agent: TLS-Certificate/1.0',
            ],
        ]);

        $data = @file_get_contents($url, false, $context);
        if (false === $data) {
            throw CRLException::notFound($url);
        }

        return $data;
    }

    /**
     * 从证书中提取CRL分发点
     *
     * @param X509Certificate $certificate 要提取CRL分发点的证书
     *
     * @return array<string> CRL分发点URL列表
     */
    public function extractCRLDistributionPoints(X509Certificate $certificate): array
    {
        $extension = $certificate->getExtension('cRLDistributionPoints');
        if (is_array($extension)) {
            $urls = [];
            foreach ($extension as $item) {
                if (is_string($item)) {
                    $urls[] = $item;
                }
            }

            return $urls;
        }

        return [];
    }
}
