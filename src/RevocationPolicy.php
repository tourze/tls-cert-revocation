<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * 定义撤销检查策略枚举
 */
enum RevocationPolicy: string implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;

    /**
     * 软失败 - 当撤销检查失败（如网络错误）时，继续验证过程
     */
    case SOFT_FAIL = 'soft_fail';

    /**
     * 硬失败 - 当撤销检查失败时，视为验证失败
     */
    case HARD_FAIL = 'hard_fail';

    /**
     * 仅CRL - 只使用CRL进行撤销检查
     */
    case CRL_ONLY = 'crl_only';

    /**
     * 仅OCSP - 只使用OCSP进行撤销检查
     */
    case OCSP_ONLY = 'ocsp_only';

    /**
     * OCSP优先 - 先尝试OCSP，失败后使用CRL
     */
    case OCSP_PREFERRED = 'ocsp_preferred';

    /**
     * CRL优先 - 先尝试CRL，失败后使用OCSP
     */
    case CRL_PREFERRED = 'crl_preferred';

    /**
     * 禁用 - 不进行任何撤销检查
     */
    case DISABLED = 'disabled';

    /**
     * 获取枚举标签
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::SOFT_FAIL => '软失败',
            self::HARD_FAIL => '硬失败',
            self::CRL_ONLY => '仅CRL',
            self::OCSP_ONLY => '仅OCSP',
            self::OCSP_PREFERRED => 'OCSP优先',
            self::CRL_PREFERRED => 'CRL优先',
            self::DISABLED => '禁用',
        };
    }
}
