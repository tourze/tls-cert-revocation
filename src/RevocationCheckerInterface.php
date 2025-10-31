<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation;

use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * 定义证书撤销检查器的接口
 */
interface RevocationCheckerInterface
{
    /**
     * 检查证书是否已被撤销
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return bool 如果证书未被撤销，返回true；如果已撤销或无法确认状态，返回false
     */
    public function check(X509Certificate $certificate, X509Certificate $issuer): bool;

    /**
     * 获取上次检查的结果详情
     *
     * @return array<string, mixed> 包含状态详情的数组
     */
    public function getLastCheckStatus(): array;
}
