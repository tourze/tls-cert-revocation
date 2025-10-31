<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCertRevocation\Exception\CRLException;

/**
 * @internal
 */
#[CoversClass(CRLException::class)]
final class CRLExceptionTest extends AbstractExceptionTestCase
{
    public function testConstructor(): void
    {
        $exception = new CRLException(
            'Test message',
            100,
            null,
            'CN=Test Issuer',
            '12345'
        );

        $this->assertSame('Test message', $exception->getMessage());
        $this->assertSame(100, $exception->getCode());
        $this->assertSame('CN=Test Issuer', $exception->getCRLIssuer());
        $this->assertSame('12345', $exception->getCRLNumber());
    }

    public function testConstructorWithDefaults(): void
    {
        $exception = new CRLException();

        $this->assertSame('', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testParseError(): void
    {
        $exception = CRLException::parseError('Invalid format', 'CN=Test Issuer', '12345');

        $this->assertSame('无法解析CRL: Invalid format', $exception->getMessage());
        $this->assertSame(2001, $exception->getCode());
        $this->assertSame('CN=Test Issuer', $exception->getCRLIssuer());
        $this->assertSame('12345', $exception->getCRLNumber());
    }

    public function testParseErrorWithoutOptionalParameters(): void
    {
        $exception = CRLException::parseError('Invalid format');

        $this->assertSame('无法解析CRL: Invalid format', $exception->getMessage());
        $this->assertSame(2001, $exception->getCode());
        $this->assertNull($exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testSignatureVerificationFailed(): void
    {
        $exception = CRLException::signatureVerificationFailed('CN=Test Issuer', '12345');

        $this->assertSame('CRL签名验证失败', $exception->getMessage());
        $this->assertSame(2002, $exception->getCode());
        $this->assertSame('CN=Test Issuer', $exception->getCRLIssuer());
        $this->assertSame('12345', $exception->getCRLNumber());
    }

    public function testSignatureVerificationFailedWithoutOptionalParameters(): void
    {
        $exception = CRLException::signatureVerificationFailed();

        $this->assertSame('CRL签名验证失败', $exception->getMessage());
        $this->assertSame(2002, $exception->getCode());
        $this->assertNull($exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testExpired(): void
    {
        $exception = CRLException::expired('2023-12-31', 'CN=Test Issuer', '12345');

        $this->assertSame('CRL已过期，下次更新时间: 2023-12-31', $exception->getMessage());
        $this->assertSame(2003, $exception->getCode());
        $this->assertSame('CN=Test Issuer', $exception->getCRLIssuer());
        $this->assertSame('12345', $exception->getCRLNumber());
    }

    public function testExpiredWithoutOptionalParameters(): void
    {
        $exception = CRLException::expired('2023-12-31');

        $this->assertSame('CRL已过期，下次更新时间: 2023-12-31', $exception->getMessage());
        $this->assertSame(2003, $exception->getCode());
        $this->assertNull($exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testNotFound(): void
    {
        $exception = CRLException::notFound('http://crl.example.com/test.crl');

        $this->assertSame('无法获取CRL: http://crl.example.com/test.crl', $exception->getMessage());
        $this->assertSame(2004, $exception->getCode());
        $this->assertNull($exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testIssuerMismatch(): void
    {
        $exception = CRLException::issuerMismatch('CN=Expected Issuer', 'CN=Actual Issuer');

        $this->assertSame('CRL颁发者不匹配，期望: CN=Expected Issuer, 实际: CN=Actual Issuer', $exception->getMessage());
        $this->assertSame(2005, $exception->getCode());
        $this->assertSame('CN=Actual Issuer', $exception->getCRLIssuer());
        $this->assertNull($exception->getCRLNumber());
    }

    public function testWithPreviousException(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new CRLException('Test message', 100, $previous);

        $this->assertSame($previous, $exception->getPrevious());
    }
}
