<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\CRL;

use Tourze\TLSCertRevocation\Crypto\SignatureVerifier;
use Tourze\TLSCertRevocation\Exception\CRLException;
use Tourze\TLSCertRevocation\Validator\ValidationResult;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * CRL验证器 - 验证证书撤销列表的有效性
 */
class CRLValidator
{
    /**
     * 构造函数
     *
     * @param SignatureVerifier|null $signatureVerifier 签名验证器
     */
    public function __construct(
        private readonly ?SignatureVerifier $signatureVerifier = null,
    ) {
    }

    /**
     * 验证CRL的有效性
     *
     * @param CertificateRevocationList $crl        要验证的CRL
     * @param X509Certificate|null      $issuerCert 颁发者证书，如果为null则使用CRL中设置的颁发者证书
     * @param ValidationResult|null     $result     验证结果，如果为null则创建新的
     *
     * @return ValidationResult 验证结果
     */
    public function validate(
        CertificateRevocationList $crl,
        ?X509Certificate $issuerCert = null,
        ?ValidationResult $result = null,
    ): ValidationResult {
        $result ??= new ValidationResult();

        try {
            $actualIssuerCert = $this->validateIssuer($crl, $issuerCert, $result);

            if (null === $actualIssuerCert) {
                return $result;
            }

            $this->validateExpiry($crl, $result);
            $this->validateSignature($crl, $actualIssuerCert, $result);

            if ($result->isValid()) {
                $result->addSuccess('CRL验证通过');
            }

            return $result;
        } catch (CRLException $e) {
            $result->addError('CRL验证失败: ' . $e->getMessage());

            return $result;
        } catch (\Throwable $e) {
            $result->addError('CRL验证过程中发生未预期错误: ' . $e->getMessage());

            return $result;
        }
    }

    /**
     * 检查证书是否被撤销
     *
     * @param X509Certificate           $certificate 要检查的证书
     * @param CertificateRevocationList $crl         用于检查的CRL
     * @param ValidationResult|null     $result      验证结果，如果为null则创建新的
     *
     * @return ValidationResult 验证结果
     */
    public function checkRevocation(
        X509Certificate $certificate,
        CertificateRevocationList $crl,
        ?ValidationResult $result = null,
    ): ValidationResult {
        $result ??= new ValidationResult();

        try {
            if (!$this->isCRLValidForCertificate($certificate, $crl)) {
                $result->addError('CRL颁发者与证书颁发者不匹配');

                return $result;
            }

            $this->validate($crl, null, $result);
            if (!$result->isValid()) {
                return $result;
            }

            $serialNumber = $this->getSerialNumber($certificate, $result);
            if (null === $serialNumber) {
                return $result;
            }

            return $this->checkCertificateRevocationStatus($crl, $serialNumber, $result);
        } catch (CRLException $e) {
            $result->addError('证书撤销检查失败: ' . $e->getMessage());

            return $result;
        } catch (\Throwable $e) {
            $result->addError('证书撤销检查过程中发生未预期错误: ' . $e->getMessage());

            return $result;
        }
    }

    /**
     * 检查证书颁发者是否匹配CRL颁发者
     *
     * @param X509Certificate           $certificate 要检查的证书
     * @param CertificateRevocationList $crl         要检查的CRL
     *
     * @return bool 如果颁发者匹配则返回true
     */
    private function isCRLValidForCertificate(X509Certificate $certificate, CertificateRevocationList $crl): bool
    {
        // 获取证书的颁发者可分辨名称
        $certIssuerDN = $certificate->getIssuerDN();

        // 获取CRL的颁发者可分辨名称
        $crlIssuerDN = $crl->getIssuerDN();

        // 比较颁发者
        return $certIssuerDN === $crlIssuerDN;
    }

    /**
     * 判断证书是否已被撤销
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return bool 如果证书已被撤销返回true，未被撤销返回false
     */
    public function isRevoked(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        // 这里需要实现实际的CRL检查逻辑
        // 这是一个简化的示例，实际应用中需要检索和验证CRL

        return false; // 默认返回未撤销
    }

    /**
     * 验证CRL颁发者
     *
     * @param CertificateRevocationList $crl        CRL
     * @param X509Certificate|null      $issuerCert 颁发者证书
     * @param ValidationResult          $result     验证结果
     *
     * @return X509Certificate|null 验证后的颁发者证书
     */
    private function validateIssuer(
        CertificateRevocationList $crl,
        ?X509Certificate $issuerCert,
        ValidationResult $result,
    ): ?X509Certificate {
        $actualIssuerCert = $issuerCert ?? $crl->getIssuerCertificate();

        if (null === $actualIssuerCert) {
            $result->addError('未提供CRL颁发者证书');

            return null;
        }

        if ($actualIssuerCert->getSubjectDN() !== $crl->getIssuerDN()) {
            $result->addError('CRL颁发者与证书主题不匹配');

            return null;
        }

        return $actualIssuerCert;
    }

    /**
     * 验证CRL有效期
     *
     * @param CertificateRevocationList $crl    CRL
     * @param ValidationResult          $result 验证结果
     */
    private function validateExpiry(CertificateRevocationList $crl, ValidationResult $result): void
    {
        $now = new \DateTimeImmutable();

        if ($crl->getThisUpdate() > $now) {
            $result->addError('CRL尚未生效');

            return;
        }

        if ($crl->isExpired()) {
            $result->addWarning('CRL已过期');
        }
    }

    /**
     * 获取证书序列号
     *
     * @param X509Certificate  $certificate 证书
     * @param ValidationResult $result      验证结果
     *
     * @return string|null 序列号，如果获取失败返回null
     */
    private function getSerialNumber(X509Certificate $certificate, ValidationResult $result): ?string
    {
        $serialNumber = $certificate->getSerialNumber();

        if (null === $serialNumber) {
            $result->addError('无法获取证书序列号');
        }

        return $serialNumber;
    }

    /**
     * 检查证书撤销状态
     *
     * @param CertificateRevocationList $crl          CRL
     * @param string                    $serialNumber 证书序列号
     * @param ValidationResult          $result       验证结果
     *
     * @return ValidationResult 验证结果
     */
    private function checkCertificateRevocationStatus(
        CertificateRevocationList $crl,
        string $serialNumber,
        ValidationResult $result,
    ): ValidationResult {
        if (!$crl->isRevoked($serialNumber)) {
            $result->addInfo('证书未被撤销');
            $result->addSuccess('证书撤销检查通过');

            return $result;
        }

        return $this->processRevokedCertificate($crl, $serialNumber, $result);
    }

    /**
     * 处理被撤销的证书
     *
     * @param CertificateRevocationList $crl          CRL
     * @param string                    $serialNumber 证书序列号
     * @param ValidationResult          $result       验证结果
     *
     * @return ValidationResult 验证结果
     */
    private function processRevokedCertificate(
        CertificateRevocationList $crl,
        string $serialNumber,
        ValidationResult $result,
    ): ValidationResult {
        $revokedCert = $crl->getRevokedCertificate($serialNumber);

        if (null === $revokedCert) {
            $result->addError('无法获取撤销证书信息');

            return $result;
        }

        if (8 === $revokedCert->getReason()) { // 8 = REMOVE_FROM_CRL
            $result->addInfo('证书已从CRL中移除');
            $result->addSuccess('证书撤销检查通过');

            return $result;
        }

        $revocationDate = $revokedCert->getRevocationDate()->format('Y-m-d H:i:s');
        $reason = $revokedCert->getReasonText();
        $result->addError('证书已被撤销，撤销时间: ' . $revocationDate . ', 原因: ' . $reason);

        return $result;
    }

    /**
     * 验证CRL签名
     *
     * @param CertificateRevocationList $crl        CRL
     * @param X509Certificate           $issuerCert 颁发者证书
     * @param ValidationResult          $result     验证结果
     */
    private function validateSignature(
        CertificateRevocationList $crl,
        X509Certificate $issuerCert,
        ValidationResult $result,
    ): void {
        if (!$this->canVerifySignature($crl)) {
            $result->addWarning('跳过CRL签名验证');

            return;
        }

        $isSignatureValid = $this->verifySignature($crl, $issuerCert);

        if (!$isSignatureValid) {
            $result->addError('CRL签名无效');

            return;
        }

        $result->addInfo('CRL签名验证通过');
    }

    /**
     * 检查是否可以验证签名
     *
     * @param CertificateRevocationList $crl CRL
     *
     * @return bool 是否可以验证
     */
    private function canVerifySignature(CertificateRevocationList $crl): bool
    {
        return null !== $this->signatureVerifier
            && null !== $crl->getSignatureAlgorithm()
            && null !== $crl->getSignatureValue()
            && null !== $crl->getRawData();
    }

    /**
     * 执行签名验证
     *
     * @param CertificateRevocationList $crl        CRL
     * @param X509Certificate           $issuerCert 颁发者证书
     *
     * @return bool 签名是否有效
     */
    private function verifySignature(CertificateRevocationList $crl, X509Certificate $issuerCert): bool
    {
        if (null === $this->signatureVerifier) {
            return false;
        }

        $issuerPublicKey = $issuerCert->getPublicKey();
        $signatureValue = $crl->getSignatureValue();
        $signatureAlgorithm = $crl->getSignatureAlgorithm();
        $rawData = $crl->getRawData();

        if (null === $issuerPublicKey || null === $signatureValue || null === $signatureAlgorithm || null === $rawData) {
            return false;
        }

        return $this->signatureVerifier->verify(
            $rawData,
            $signatureValue,
            $issuerPublicKey,
            $signatureAlgorithm
        );
    }
}
