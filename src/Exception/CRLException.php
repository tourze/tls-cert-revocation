<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Exception;

/**
 * CRL异常 - 当CRL处理过程中发生错误时抛出
 */
class CRLException extends \Exception
{
    /**
     * 构造函数
     *
     * @param string          $message   异常消息
     * @param int             $code      异常代码
     * @param \Throwable|null $previous  前一个异常
     * @param string|null     $crlIssuer CRL颁发者
     * @param string|null     $crlNumber CRL序列号
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        private readonly ?string $crlIssuer = null,
        private readonly ?string $crlNumber = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    /**
     * 获取CRL颁发者
     */
    public function getCRLIssuer(): ?string
    {
        return $this->crlIssuer;
    }

    /**
     * 获取CRL序列号
     */
    public function getCRLNumber(): ?string
    {
        return $this->crlNumber;
    }

    /**
     * 创建CRL解析错误异常
     *
     * @param string      $detail    错误详情
     * @param string|null $crlIssuer CRL颁发者
     * @param string|null $crlNumber CRL序列号
     */
    public static function parseError(string $detail, ?string $crlIssuer = null, ?string $crlNumber = null): self
    {
        $message = "无法解析CRL: {$detail}";

        return new self($message, 2001, null, $crlIssuer, $crlNumber);
    }

    /**
     * 创建CRL签名验证失败异常
     *
     * @param string|null $crlIssuer CRL颁发者
     * @param string|null $crlNumber CRL序列号
     */
    public static function signatureVerificationFailed(?string $crlIssuer = null, ?string $crlNumber = null): self
    {
        $message = 'CRL签名验证失败';

        return new self($message, 2002, null, $crlIssuer, $crlNumber);
    }

    /**
     * 创建CRL已过期异常
     *
     * @param string      $nextUpdate 下次更新时间
     * @param string|null $crlIssuer  CRL颁发者
     * @param string|null $crlNumber  CRL序列号
     */
    public static function expired(string $nextUpdate, ?string $crlIssuer = null, ?string $crlNumber = null): self
    {
        $message = "CRL已过期，下次更新时间: {$nextUpdate}";

        return new self($message, 2003, null, $crlIssuer, $crlNumber);
    }

    /**
     * 创建找不到CRL异常
     *
     * @param string $location CRL位置
     */
    public static function notFound(string $location): self
    {
        $message = "无法获取CRL: {$location}";

        return new self($message, 2004);
    }

    /**
     * 创建CRL颁发者不匹配异常
     *
     * @param string $expectedIssuer 期望的颁发者
     * @param string $actualIssuer   实际颁发者
     */
    public static function issuerMismatch(string $expectedIssuer, string $actualIssuer): self
    {
        $message = "CRL颁发者不匹配，期望: {$expectedIssuer}, 实际: {$actualIssuer}";

        return new self($message, 2005, null, $actualIssuer);
    }
}
