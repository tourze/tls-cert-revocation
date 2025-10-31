<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCertRevocation\Exception\OCSPException;

/**
 * @internal
 */
#[CoversClass(OCSPException::class)]
final class OCSPExceptionTest extends AbstractExceptionTestCase
{
    public function testRequestFailed(): void
    {
        $exception = OCSPException::requestFailed('Network error');

        $this->assertSame('OCSP请求失败: Network error', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testRequestFailedWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = OCSPException::requestFailed('Network error', $previous);

        $this->assertSame('OCSP请求失败: Network error', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testParseError(): void
    {
        $exception = OCSPException::parseError('Invalid format');

        $this->assertSame('OCSP响应解析错误: Invalid format', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testParseErrorWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = OCSPException::parseError('Invalid format', $previous);

        $this->assertSame('OCSP响应解析错误: Invalid format', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testConnectionFailed(): void
    {
        $exception = OCSPException::connectionFailed('http://ocsp.example.com');

        $this->assertSame('无法连接到OCSP服务器: http://ocsp.example.com', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testConnectionFailedWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = OCSPException::connectionFailed('http://ocsp.example.com', $previous);

        $this->assertSame('无法连接到OCSP服务器: http://ocsp.example.com', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testValidationFailed(): void
    {
        $exception = OCSPException::validationFailed('Signature mismatch');

        $this->assertSame('OCSP响应验证失败: Signature mismatch', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testValidationFailedWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = OCSPException::validationFailed('Signature mismatch', $previous);

        $this->assertSame('OCSP响应验证失败: Signature mismatch', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testCertificateRevokedWithSerialNumberOnly(): void
    {
        $exception = OCSPException::certificateRevoked('12345');

        $this->assertSame('证书已被撤销 (序列号: 12345)', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCertificateRevokedWithReason(): void
    {
        $exception = OCSPException::certificateRevoked('12345', 'Key compromise');

        $this->assertSame('证书已被撤销 (序列号: 12345), 原因: Key compromise', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCertificateRevokedWithDate(): void
    {
        $exception = OCSPException::certificateRevoked('12345', null, '2023-12-31');

        $this->assertSame('证书已被撤销 (序列号: 12345), 撤销日期: 2023-12-31', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCertificateRevokedWithAllParameters(): void
    {
        $exception = OCSPException::certificateRevoked('12345', 'Key compromise', '2023-12-31');

        $this->assertSame('证书已被撤销 (序列号: 12345), 原因: Key compromise, 撤销日期: 2023-12-31', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testExtendsRuntimeException(): void
    {
        $exception = new OCSPException('Test message');

        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }
}
