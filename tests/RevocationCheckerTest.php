<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\Exception\RevocationCheckException;
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSCertRevocation\OCSP\OCSPResponse;
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(RevocationChecker::class)]
final class RevocationCheckerTest extends TestCase
{
    private X509Certificate $certificate;

    private X509Certificate $issuer;

    /**
     * @var OCSPClient&\PHPUnit\Framework\MockObject\MockObject
     */
    private OCSPClient $ocspClient;

    /**
     * @var CRLValidator&\PHPUnit\Framework\MockObject\MockObject
     */
    private CRLValidator $crlValidator;

    protected function setUp(): void
    {
        parent::setUp();

        // 使用真实的 X509Certificate 实例
        $this->certificate = new X509Certificate();
        $this->issuer = new X509Certificate();

        // OCSPClient 需要 Mock，因为它涉及网络请求
        $this->ocspClient = $this->createMock(OCSPClient::class);

        // CRLValidator 需要 Mock，因为 isRevoked 方法默认总是返回 false
        $this->crlValidator = $this->createMock(CRLValidator::class);
    }

    /**
     * 创建一个具有特定状态的 OCSPResponse
     */
    private function createOCSPResponse(int $certStatus): OCSPResponse
    {
        $response = $this->createMock(OCSPResponse::class);
        $response->method('getCertStatus')->willReturn($certStatus);

        return $response;
    }

    public function testCheckWithDisabledPolicyReturnsTrue(): void
    {
        $checker = new RevocationChecker(
            RevocationPolicy::DISABLED,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('disabled', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
    }

    public function testCheckWithOCSPOnlyWhenCertificateIsGoodReturnsTrue(): void
    {
        $ocspResponse = $this->createOCSPResponse(0); // 0 = good

        // 配置OCSP客户端返回"good"状态
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willReturn($ocspResponse)
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::OCSP_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('ocsp_only', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
        $this->assertEquals(['ocsp'], $checker->getLastCheckStatus()['methods_tried']);
        $this->assertEquals('good', $checker->getLastCheckStatus()['ocsp_status']);
    }

    public function testCheckWithOCSPOnlyWhenCertificateIsRevokedReturnsFalse(): void
    {
        $ocspResponse = $this->createOCSPResponse(1); // 1 = revoked

        // 配置OCSP客户端返回"revoked"状态
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willReturn($ocspResponse)
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::OCSP_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertFalse($result);
        $this->assertEquals('ocsp_only', $checker->getLastCheckStatus()['policy']);
        $this->assertFalse($checker->getLastCheckStatus()['result']);
        $this->assertEquals(['ocsp'], $checker->getLastCheckStatus()['methods_tried']);
        $this->assertEquals('revoked', $checker->getLastCheckStatus()['ocsp_status']);
    }

    public function testCheckWithOCSPOnlyWhenOCSPFailsThrowsException(): void
    {
        // 配置OCSP客户端抛出异常
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willThrowException(new \Exception('OCSP服务器不可用'))
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::OCSP_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $this->expectException(RevocationCheckException::class);
        $this->expectExceptionMessage('OCSP检查失败');

        $checker->check($this->certificate, $this->issuer);
    }

    public function testCheckWithCRLOnlyWhenCertificateIsNotRevokedReturnsTrue(): void
    {
        // 配置颁发者证书返回CRL分发点（使用 setExtensions 方法）
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => ['http://crl.example.com/ca.crl'],
        ]);

        // 配置CRL验证器返回证书未被撤销
        $this->crlValidator->method('isRevoked')
            ->with($this->certificate, $this->issuer)
            ->willReturn(false)
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::CRL_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('crl_only', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
        $this->assertEquals(['crl'], $checker->getLastCheckStatus()['methods_tried']);
        $this->assertEquals('good', $checker->getLastCheckStatus()['crl_status']);
    }

    public function testCheckWithCRLOnlyWhenCertificateIsRevokedReturnsFalse(): void
    {
        // 配置颁发者证书返回CRL分发点
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => ['http://crl.example.com/ca.crl'],
        ]);

        // 配置CRL验证器返回证书已被撤销
        $this->crlValidator->method('isRevoked')
            ->with($this->certificate, $this->issuer)
            ->willReturn(true)
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::CRL_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertFalse($result);
        $this->assertEquals('crl_only', $checker->getLastCheckStatus()['policy']);
        $this->assertFalse($checker->getLastCheckStatus()['result']);
        $this->assertEquals(['crl'], $checker->getLastCheckStatus()['methods_tried']);
        $this->assertEquals('revoked', $checker->getLastCheckStatus()['crl_status']);
    }

    public function testCheckWithCRLOnlyWhenNoCRLDistributionPointsThrowsException(): void
    {
        // 配置颁发者证书返回空的CRL分发点
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => [],
        ]);

        $checker = new RevocationChecker(
            RevocationPolicy::CRL_ONLY,
            $this->ocspClient,
            $this->crlValidator
        );

        $this->expectException(RevocationCheckException::class);
        $this->expectExceptionMessage('颁发者证书中未找到CRL分发点');

        $checker->check($this->certificate, $this->issuer);
    }

    public function testCheckWithOCSPPreferredWhenOCSPSucceedsDoesNotCheckCRL(): void
    {
        $ocspResponse = $this->createOCSPResponse(0); // 0 = good

        // 配置OCSP客户端返回"good"状态
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willReturn($ocspResponse)
        ;

        // CRL验证器不应被调用
        $this->crlValidator->expects($this->never())->method('isRevoked');

        $checker = new RevocationChecker(
            RevocationPolicy::OCSP_PREFERRED,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('ocsp_preferred', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
        $this->assertEquals(['ocsp'], $checker->getLastCheckStatus()['methods_tried']);
    }

    public function testCheckWithOCSPPreferredWhenOCSPFailsFallbackToCRL(): void
    {
        // 配置OCSP客户端抛出异常
        $this->ocspClient->method('checkCertificate')
            ->willThrowException(new \Exception('OCSP服务器不可用'))
        ;

        // 配置颁发者证书返回CRL分发点
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => ['http://crl.example.com/ca.crl'],
        ]);

        // 配置CRL验证器返回证书未被撤销
        $this->crlValidator->method('isRevoked')
            ->with($this->certificate, $this->issuer)
            ->willReturn(false)
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::OCSP_PREFERRED,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('ocsp_preferred', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
        $this->assertContains('ocsp', $checker->getLastCheckStatus()['methods_tried']);
        $this->assertContains('crl', $checker->getLastCheckStatus()['methods_tried']);
    }

    public function testCheckWithSoftFailWhenAllMethodsFailReturnsTrue(): void
    {
        // 配置OCSP客户端抛出异常
        $this->ocspClient->method('checkCertificate')
            ->willThrowException(new \Exception('OCSP服务器不可用'))
        ;

        // 配置颁发者证书返回CRL分发点
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => ['http://crl.example.com/ca.crl'],
        ]);

        // 配置CRL验证器抛出异常
        $this->crlValidator->method('isRevoked')
            ->willThrowException(new \Exception('CRL检查失败'))
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::SOFT_FAIL,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertTrue($result);
        $this->assertEquals('soft_fail', $checker->getLastCheckStatus()['policy']);
        $this->assertTrue($checker->getLastCheckStatus()['result']);
        $this->assertContains('ocsp', $checker->getLastCheckStatus()['methods_tried']);
        $this->assertContains('crl', $checker->getLastCheckStatus()['methods_tried']);
        $this->assertArrayHasKey('ocsp_error', $checker->getLastCheckStatus());
    }

    public function testCheckWithHardFailWhenAllMethodsFailReturnsFalse(): void
    {
        // 配置OCSP客户端抛出异常
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willThrowException(new \Exception('OCSP服务器不可用'))
        ;

        // 配置颁发者证书返回CRL分发点
        $this->issuer->setExtensions([
            'cRLDistributionPoints' => ['http://crl.example.com/ca.crl'],
        ]);

        // 配置CRL验证器抛出异常
        $this->crlValidator->method('isRevoked')
            ->willThrowException(new \Exception('CRL服务器不可用'))
        ;

        $checker = new RevocationChecker(
            RevocationPolicy::HARD_FAIL,
            $this->ocspClient,
            $this->crlValidator
        );

        $result = $checker->check($this->certificate, $this->issuer);

        $this->assertFalse($result);
        $this->assertEquals('hard_fail', $checker->getLastCheckStatus()['policy']);
        $this->assertFalse($checker->getLastCheckStatus()['result']);
        $this->assertContains('ocsp', $checker->getLastCheckStatus()['methods_tried']);
        $this->assertContains('crl', $checker->getLastCheckStatus()['methods_tried']);
        $this->assertArrayHasKey('ocsp_error', $checker->getLastCheckStatus());
        $this->assertArrayHasKey('crl_error', $checker->getLastCheckStatus());
    }

    public function testSetPolicyChangesPolicy(): void
    {
        $checker = new RevocationChecker(
            RevocationPolicy::DISABLED,
            $this->ocspClient,
            $this->crlValidator
        );

        $this->assertEquals(RevocationPolicy::DISABLED, $checker->getPolicy());

        $checker->setPolicy(RevocationPolicy::HARD_FAIL);

        $this->assertEquals(RevocationPolicy::HARD_FAIL, $checker->getPolicy());
    }
}
