<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Example;

use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;
use Tourze\TLSCertRevocation\CRL\CRLCache;
use Tourze\TLSCertRevocation\CRL\CRLParser;
use Tourze\TLSCertRevocation\CRL\CRLUpdater;
use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\Crypto\SignatureVerifier;
use Tourze\TLSCertRevocation\Validator\ValidationResult;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * CRL验证示例
 */
class ValidateCRLExample
{
    /**
     * @var CRLCache CRL缓存
     */
    private CRLCache $crlCache;

    /**
     * @var CRLParser CRL解析器
     */
    private CRLParser $crlParser;

    /**
     * @var CRLUpdater CRL更新器
     */
    private CRLUpdater $crlUpdater;

    /**
     * @var CRLValidator CRL验证器
     */
    private CRLValidator $crlValidator;

    /**
     * 构造函数
     */
    public function __construct(?SignatureVerifier $signatureVerifier = null)
    {
        $this->crlCache = new CRLCache();
        $this->crlParser = new CRLParser();
        $this->crlUpdater = new CRLUpdater($this->crlParser, $this->crlCache);
        $this->crlValidator = new CRLValidator($signatureVerifier);
    }

    /**
     * 验证证书是否被撤销
     *
     * @param X509Certificate $certificate 要验证的证书
     * @param bool            $forceUpdate 是否强制更新CRL
     *
     * @return ValidationResult 验证结果
     */
    public function validateCertificateRevocation(
        X509Certificate $certificate,
        bool $forceUpdate = false,
    ): ValidationResult {
        $result = new ValidationResult();

        try {
            // 获取证书颁发者
            $issuerDN = $certificate->getIssuerDN();
            if (null === $issuerDN) {
                $result->addError('无法获取证书颁发者信息');

                return $result;
            }

            // 检查是否有缓存的CRL
            $crl = $this->crlCache->get($issuerDN);

            // 如果没有CRL或强制更新，尝试获取
            if (null === $crl || $forceUpdate || $this->crlCache->isExpiringSoon($issuerDN)) {
                $crl = $this->crlUpdater->updateFromCertificate($certificate, true);

                if (null === $crl) {
                    $result->addWarning('无法获取CRL，继续但不进行撤销检查');

                    return $result;
                }
            }

            // 检查证书撤销状态
            $revocationResult = $this->crlValidator->checkRevocation($certificate, $crl);

            // 将撤销检查结果合并到验证结果中
            $result->merge($revocationResult);

            return $result;
        } catch (\Throwable $e) {
            $result->addError('证书撤销验证失败: ' . $e->getMessage());

            return $result;
        }
    }

    /**
     * 显示验证结果
     *
     * @param ValidationResult $result 验证结果
     *
     * @return string 格式化的结果输出
     */
    public function formatValidationResult(ValidationResult $result): string
    {
        $output = [];

        $output[] = '证书撤销状态验证结果:';
        $output[] = '有效性: ' . ($result->isValid() ? '有效' : '无效');

        $output = array_merge($output, $this->addErrors($result));
        $output = array_merge($output, $this->addWarnings($result));
        $output = array_merge($output, $this->addInfoMessages($result));
        $output = array_merge($output, $this->addSuccessMessages($result));

        return implode("\n", $output);
    }

    /**
     * 在控制台输出CRL统计信息
     *
     * @return string CRL统计信息
     */
    public function printCRLStats(): string
    {
        $output = [];
        $output[] = 'CRL缓存统计信息:';
        $output[] = '- 缓存的CRL数量: ' . $this->crlCache->count();

        $issuers = $this->crlCache->getIssuers();

        if ([] !== $issuers) {
            $output = array_merge($output, $this->addIssuerDetails($issuers));
        }

        return implode("\n", $output);
    }

    /**
     * 添加错误信息到输出
     *
     * @param ValidationResult $result 验证结果
     *
     * @return array<string> 错误信息数组
     */
    private function addErrors(ValidationResult $result): array
    {
        if ([] !== $result->getErrors()) {
            $output = [];
            $output[] = "\n错误:";
            foreach ($result->getErrors() as $error) {
                $output[] = '- ' . $error;
            }

            return $output;
        }

        return [];
    }

    /**
     * 添加警告信息到输出
     *
     * @param ValidationResult $result 验证结果
     *
     * @return array<string> 警告信息数组
     */
    private function addWarnings(ValidationResult $result): array
    {
        if ([] !== $result->getWarnings()) {
            $output = [];
            $output[] = "\n警告:";
            foreach ($result->getWarnings() as $warning) {
                $output[] = '- ' . $warning;
            }

            return $output;
        }

        return [];
    }

    /**
     * 添加信息消息到输出
     *
     * @param ValidationResult $result 验证结果
     *
     * @return array<string> 信息消息数组
     */
    private function addInfoMessages(ValidationResult $result): array
    {
        if ([] !== $result->getInfoMessages()) {
            $output = [];
            $output[] = "\n信息:";
            foreach ($result->getInfoMessages() as $info) {
                $output[] = '- ' . $info;
            }

            return $output;
        }

        return [];
    }

    /**
     * 添加成功消息到输出
     *
     * @param ValidationResult $result 验证结果
     *
     * @return array<string> 成功消息数组
     */
    private function addSuccessMessages(ValidationResult $result): array
    {
        if ([] !== $result->getSuccessMessages()) {
            $output = [];
            $output[] = "\n成功:";
            foreach ($result->getSuccessMessages() as $success) {
                $output[] = '- ' . $success;
            }

            return $output;
        }

        return [];
    }

    /**
     * 添加颁发者详细信息到输出
     *
     * @param array<string> $issuers 颁发者列表
     *
     * @return array<string> 颁发者详细信息数组
     */
    private function addIssuerDetails(array $issuers): array
    {
        $output = [];
        $output[] = '- 缓存的颁发者:';

        foreach ($issuers as $issuer) {
            $crl = $this->crlCache->get($issuer);
            if (null !== $crl) {
                $output = array_merge($output, $this->addSingleIssuerDetails($issuer, $crl));
            }
        }

        return $output;
    }

    /**
     * 添加单个颁发者的详细信息到输出
     *
     * @param string                    $issuer 颁发者DN
     * @param CertificateRevocationList $crl    CRL对象
     *
     * @return array<string> 单个颁发者详细信息数组
     */
    private function addSingleIssuerDetails(string $issuer, CertificateRevocationList $crl): array
    {
        $nextUpdate = $crl->getNextUpdate();
        $nextUpdateStr = null !== $nextUpdate ? $nextUpdate->format('Y-m-d H:i:s') : '未指定';
        $isExpiring = $this->crlCache->isExpiringSoon($issuer);
        $status = $isExpiring ? '即将过期' : '有效';

        $output = [];
        $output[] = "  * {$issuer}";
        $output[] = "    - 下次更新: {$nextUpdateStr}";
        $output[] = "    - 状态: {$status}";
        $output[] = "    - CRL序号: {$crl->getCRLNumber()}";
        $output[] = '    - 撤销证书数量: ' . count($crl->getRevokedCertificates());

        return $output;
    }
}
