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

    private OCSPClient $ocspClient;

    private CRLValidator $crlValidator;

    protected function setUp(): void
    {
        parent::setUp();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $this->certificate = new class extends X509Certificate {
            /** @return array<string, string> */
            public function getSubject(): array
            {
                return ['CN' => 'example.com'];
            }

            // 可重写的方法供测试使用
            public function getIssuerDN(bool $derFormat = false): ?string
            {
                return null; // 默认值，可在具体测试中覆盖
            }

            public function getSerialNumber(): ?string
            {
                return null; // 默认值，可在具体测试中覆盖
            }

            public function getExtension(string $oid): mixed
            {
                return null; // 默认值，可在具体测试中覆盖
            }
        };

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $this->issuer = new class extends X509Certificate {
            /** @var array<string, mixed> */
            private array $extensionResponses = [];

            /** @return array<string, string> */
            public function getSubject(): array
            {
                return ['CN' => 'Example CA'];
            }

            // 可重写的方法供测试使用
            public function getExtension(string $oid): mixed
            {
                return $this->extensionResponses[$oid] ?? null;
            }

            // 测试辅助方法：设置扩展返回值
            public function setExtensionResponse(string $oid, mixed $value): void
            {
                $this->extensionResponses[$oid] = $value;
            }
        };

        // 创建完整的OCSP客户端和CRL验证器的模拟
        $this->ocspClient = $this->getMockBuilder(OCSPClient::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['checkCertificate'])
            ->getMock()
        ;

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $this->crlValidator = new class extends CRLValidator {
            private bool $isRevokedResult = false;

            private ?\Exception $exceptionToThrow = null;

            public function setIsRevokedResult(bool $result): void
            {
                $this->isRevokedResult = $result;
            }

            public function setExceptionToThrow(?\Exception $exception): void
            {
                $this->exceptionToThrow = $exception;
            }

            public function isRevoked(X509Certificate $certificate, X509Certificate $issuer): bool
            {
                if (null !== $this->exceptionToThrow) {
                    throw $this->exceptionToThrow;
                }

                return $this->isRevokedResult;
            }
        };
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
        // 使用匿名类替代具体类createStub以符合静态分析规则
        $ocspResponse = new class extends OCSPResponse {
            public function __construct()
            {
                parent::__construct(0);
            }

            public function getCertStatus(): int
            {
                return 0;
            }
        };

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
        // 使用匿名类替代具体类createStub以符合静态分析规则
        $ocspResponse = new class extends OCSPResponse {
            public function __construct()
            {
                parent::__construct(0);
            }

            public function getCertStatus(): int
            {
                return 1;
            }
        };

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
        // 配置颁发者证书返回CRL分发点
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', ['http://crl.example.com/ca.crl']);

        // 配置CRL验证器返回证书未被撤销
        // @phpstan-ignore-next-line
        $this->crlValidator->setIsRevokedResult(false);

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
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', ['http://crl.example.com/ca.crl']);

        // 配置CRL验证器返回证书已被撤销
        // @phpstan-ignore-next-line
        $this->crlValidator->setIsRevokedResult(true);

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
        // 配置颁发者证书不返回CRL分发点
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', []);

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
        // 使用匿名类替代具体类createStub以符合静态分析规则
        $ocspResponse = new class extends OCSPResponse {
            public function __construct()
            {
                parent::__construct(0);
            }

            public function getCertStatus(): int
            {
                return 0;
            }
        };

        // 配置OCSP客户端返回"good"状态
        $this->ocspClient->method('checkCertificate')
            ->with($this->certificate, $this->issuer)
            ->willReturn($ocspResponse)
        ;

        // CRL验证器不应被调用 - 由于使用匿名类，我们无法直接验证never()调用
        // 如果isRevoked被调用，测试将失败，这提供了隐式验证

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
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', ['http://crl.example.com/ca.crl']);

        // 配置CRL验证器返回证书未被撤销
        // @phpstan-ignore-next-line
        $this->crlValidator->setIsRevokedResult(false);

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
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', ['http://crl.example.com/ca.crl']);

        // 配置CRL验证器抛出异常
        // @phpstan-ignore-next-line
        $this->crlValidator->setExceptionToThrow(new \Exception('CRL检查失败'));

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
        // @phpstan-ignore-next-line
        $this->issuer->setExtensionResponse('cRLDistributionPoints', ['http://crl.example.com/ca.crl']);

        // 配置CRL验证器抛出异常
        // @phpstan-ignore-next-line
        $this->crlValidator->setExceptionToThrow(new \Exception('CRL服务器不可用'));

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
