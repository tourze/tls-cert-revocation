<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Exception;

/**
 * OCSP异常类 - 处理OCSP相关错误
 */
class OCSPException extends \RuntimeException
{
    /**
     * 创建请求失败异常
     *
     * @param string          $message  错误信息
     * @param \Throwable|null $previous 前一个异常
     */
    public static function requestFailed(string $message, ?\Throwable $previous = null): self
    {
        return new self('OCSP请求失败: ' . $message, 0, $previous);
    }

    /**
     * 创建响应解析失败异常
     *
     * @param string          $message  错误信息
     * @param \Throwable|null $previous 前一个异常
     */
    public static function parseError(string $message, ?\Throwable $previous = null): self
    {
        return new self('OCSP响应解析错误: ' . $message, 0, $previous);
    }

    /**
     * 创建连接失败异常
     *
     * @param string          $url      OCSP服务器URL
     * @param \Throwable|null $previous 前一个异常
     */
    public static function connectionFailed(string $url, ?\Throwable $previous = null): self
    {
        return new self('无法连接到OCSP服务器: ' . $url, 0, $previous);
    }

    /**
     * 创建响应验证失败异常
     *
     * @param string          $message  错误信息
     * @param \Throwable|null $previous 前一个异常
     */
    public static function validationFailed(string $message, ?\Throwable $previous = null): self
    {
        return new self('OCSP响应验证失败: ' . $message, 0, $previous);
    }

    /**
     * 创建证书已撤销异常
     *
     * @param string      $serialNumber 证书序列号
     * @param string|null $reason       撤销原因
     * @param string|null $date         撤销日期
     */
    public static function certificateRevoked(
        string $serialNumber,
        ?string $reason = null,
        ?string $date = null,
    ): self {
        $message = '证书已被撤销 (序列号: ' . $serialNumber . ')';

        if (null !== $reason) {
            $message .= ', 原因: ' . $reason;
        }

        if (null !== $date) {
            $message .= ', 撤销日期: ' . $date;
        }

        return new self($message);
    }
}
