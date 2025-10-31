<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation;

use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\Exception\RevocationCheckException;
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * 撤销检查器，实现不同的撤销检查策略
 */
class RevocationChecker implements RevocationCheckerInterface
{
    /**
     * 上次检查结果
     * @var array<string, mixed>
     */
    private array $lastCheckStatus = [];

    /**
     * 构造函数
     *
     * @param RevocationPolicy $policy       撤销检查策略
     * @param ?OCSPClient      $ocspClient   OCSP客户端
     * @param ?CRLValidator    $crlValidator CRL验证器
     */
    public function __construct(
        private RevocationPolicy $policy = RevocationPolicy::OCSP_PREFERRED,
        private ?OCSPClient $ocspClient = null,
        private ?CRLValidator $crlValidator = null,
    ) {
        // 根据策略，确保必要的组件已初始化
        if ($this->requiresOCSP() && null === $this->ocspClient) {
            $this->ocspClient = new OCSPClient();
        }

        if ($this->requiresCRL() && null === $this->crlValidator) {
            $this->crlValidator = new CRLValidator();
        }
    }

    /**
     * 检查证书是否已被撤销
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return bool 如果证书未被撤销，返回true；如果已撤销或无法确认状态，返回false
     */
    public function check(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        $this->lastCheckStatus = [
            'policy' => $this->policy->value,
            'certificate' => $certificate->getSubject(),
            'issuer' => $issuer->getSubject(),
            'result' => false,
            'methods_tried' => [],
            'ocsp_conclusive' => false,
            'crl_conclusive' => false,
        ];

        // 如果撤销检查被禁用，直接返回true
        if (RevocationPolicy::DISABLED === $this->policy) {
            $this->lastCheckStatus['result'] = true;

            return true;
        }

        // 根据策略执行撤销检查
        switch ($this->policy) {
            case RevocationPolicy::OCSP_ONLY:
                return $this->checkOCSP($certificate, $issuer);

            case RevocationPolicy::CRL_ONLY:
                return $this->checkCRL($certificate, $issuer);

            case RevocationPolicy::OCSP_PREFERRED:
                try {
                    return $this->checkOCSP($certificate, $issuer);
                } catch (\Throwable $e) {
                    $this->lastCheckStatus['ocsp_error'] = $e->getMessage();

                    // OCSP失败，尝试CRL
                    return $this->checkCRL($certificate, $issuer);
                }

            case RevocationPolicy::CRL_PREFERRED:
                try {
                    return $this->checkCRL($certificate, $issuer);
                } catch (\Throwable $e) {
                    // CRL失败，尝试OCSP
                    return $this->checkOCSP($certificate, $issuer);
                }

            case RevocationPolicy::SOFT_FAIL:
                // 尝试所有方法，但网络错误时不失败
                try {
                    return $this->checkOCSP($certificate, $issuer);
                } catch (\Throwable $e) {
                    $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
                }

                try {
                    return $this->checkCRL($certificate, $issuer);
                } catch (\Throwable $e) {
                    $this->lastCheckStatus['crl_error'] = $e->getMessage();
                }

                // 在软失败模式下，若所有方法失败，仍然返回true
                $this->lastCheckStatus['result'] = true;

                return true;

            case RevocationPolicy::HARD_FAIL:
            default:
                // 尝试所有方法，任何错误都视为失败
                try {
                    return $this->checkOCSP($certificate, $issuer);
                } catch (\Throwable $e) {
                    $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
                }

                try {
                    return $this->checkCRL($certificate, $issuer);
                } catch (\Throwable $e) {
                    $this->lastCheckStatus['crl_error'] = $e->getMessage();

                    // 在硬失败模式下，所有方法失败时返回false
                    return false;
                }
        }
    }

    /**
     * 获取上次检查的结果详情
     *
     * @return array<string, mixed> 包含状态详情的数组
     */
    public function getLastCheckStatus(): array
    {
        return $this->lastCheckStatus;
    }

    /**
     * 设置撤销检查策略
     *
     * @param RevocationPolicy $policy 新策略
     */
    public function setPolicy(RevocationPolicy $policy): void
    {
        $this->policy = $policy;
    }

    /**
     * 获取当前撤销检查策略
     *
     * @return RevocationPolicy 当前策略
     */
    public function getPolicy(): RevocationPolicy
    {
        return $this->policy;
    }

    /**
     * 使用OCSP检查证书撤销状态
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return bool 如果证书未被撤销，返回true
     *
     * @throws RevocationCheckException 当OCSP检查发生错误时
     */
    private function checkOCSP(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        if (null === $this->ocspClient) {
            throw new RevocationCheckException('OCSP客户端未初始化，无法进行OCSP检查');
        }

        if (!isset($this->lastCheckStatus['methods_tried']) || !is_array($this->lastCheckStatus['methods_tried'])) {
            $this->lastCheckStatus['methods_tried'] = [];
        }
        $this->lastCheckStatus['methods_tried'][] = 'ocsp';

        try {
            $response = $this->ocspClient->checkCertificate($certificate, $issuer);
            $certStatus = $response->getCertStatus();

            // 将整数状态代码转换为字符串以存储在状态数组中
            $statusMap = [
                0 => 'good',
                1 => 'revoked',
                2 => 'unknown',
            ];
            $status = $statusMap[$certStatus] ?? 'unknown';

            $this->lastCheckStatus['ocsp_status'] = $status;
            $this->lastCheckStatus['ocsp_conclusive'] = true;

            // 如果状态为"good"(0)，表示证书未被撤销
            $result = 0 === $certStatus;
            $this->lastCheckStatus['result'] = $result;

            return $result;
        } catch (\Throwable $e) {
            $this->lastCheckStatus['ocsp_error'] = $e->getMessage();
            $this->lastCheckStatus['ocsp_conclusive'] = false;

            if (RevocationPolicy::HARD_FAIL === $this->policy
                || RevocationPolicy::OCSP_ONLY === $this->policy) {
                throw new RevocationCheckException('OCSP检查失败：' . $e->getMessage(), 0, $e);
            }

            // 对于其他策略，重新抛出异常以便调用方可以尝试其他方法
            throw $e;
        }
    }

    /**
     * 使用CRL检查证书撤销状态
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return bool 如果证书未被撤销，返回true
     *
     * @throws RevocationCheckException 当CRL检查发生错误时
     */
    private function checkCRL(X509Certificate $certificate, X509Certificate $issuer): bool
    {
        if (null === $this->crlValidator) {
            throw new RevocationCheckException('CRL验证器未初始化，无法进行CRL检查');
        }

        if (!isset($this->lastCheckStatus['methods_tried']) || !is_array($this->lastCheckStatus['methods_tried'])) {
            $this->lastCheckStatus['methods_tried'] = [];
        }
        $this->lastCheckStatus['methods_tried'][] = 'crl';

        try {
            // 从颁发者证书获取CRL分发点
            $crlDPs = $issuer->getExtension('cRLDistributionPoints');
            if (null === $crlDPs || [] === $crlDPs) {
                $this->lastCheckStatus['crl_error'] = '颁发者证书中未找到CRL分发点';
                $this->lastCheckStatus['crl_conclusive'] = false;

                if (RevocationPolicy::HARD_FAIL === $this->policy
                    || RevocationPolicy::CRL_ONLY === $this->policy) {
                    throw new RevocationCheckException('颁发者证书中未找到CRL分发点');
                }

                return false;
            }

            // 检查证书是否在CRL中
            $isRevoked = $this->crlValidator->isRevoked($certificate, $issuer);

            $this->lastCheckStatus['crl_status'] = $isRevoked ? 'revoked' : 'good';
            $this->lastCheckStatus['crl_conclusive'] = true;

            $result = !$isRevoked;
            $this->lastCheckStatus['result'] = $result;

            return $result;
        } catch (\Throwable $e) {
            $this->lastCheckStatus['crl_error'] = $e->getMessage();
            $this->lastCheckStatus['crl_conclusive'] = false;

            if (RevocationPolicy::HARD_FAIL === $this->policy
                || RevocationPolicy::CRL_ONLY === $this->policy) {
                throw new RevocationCheckException('CRL检查失败：' . $e->getMessage(), 0, $e);
            }

            // 对于其他策略，重新抛出异常以便调用方可以尝试其他方法
            throw $e;
        }
    }

    /**
     * 检查当前策略是否需要OCSP
     *
     * @return bool 如果需要OCSP，返回true
     */
    private function requiresOCSP(): bool
    {
        return RevocationPolicy::DISABLED !== $this->policy
               && RevocationPolicy::CRL_ONLY !== $this->policy;
    }

    /**
     * 检查当前策略是否需要CRL
     *
     * @return bool 如果需要CRL，返回true
     */
    private function requiresCRL(): bool
    {
        return RevocationPolicy::DISABLED !== $this->policy
               && RevocationPolicy::OCSP_ONLY !== $this->policy;
    }
}
