<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\OCSP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\OCSP\OCSPRequest;
use Tourze\TLSCertRevocation\OCSP\OCSPResponse;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(OCSPResponse::class)]
final class OCSPResponseTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // OCSPResponse 是一个数据模型类，需要构造函数参数，直接实例化是合理的
    }

    public function testConstructCreatesInstance(): void
    {
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);

        $this->assertInstanceOf(OCSPResponse::class, $response);
    }

    public function testMatchesRequest(): void
    {
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $mockRequest = new class extends OCSPRequest {
            public function __construct()
            {
                parent::__construct('123', 'test-name-hash', 'test-key-hash');
            }

            public function getNonce(): ?string
            {
                return null;
            }

            public function getSerialNumber(): string
            {
                return '12345';
            }

            public function getIssuerNameHash(): string
            {
                return 'name-hash';
            }

            public function getIssuerKeyHash(): string
            {
                return 'key-hash';
            }
        };

        $result = $response->matchesRequest($mockRequest);

        $this->assertIsBool($result);
    }

    public function testVerifyNonce(): void
    {
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);
        $testNonce = 'test-nonce-123';

        $result = $response->verifyNonce($testNonce);

        $this->assertIsBool($result);
        $this->assertFalse($result);
    }

    public function testVerifySignature(): void
    {
        $response = new OCSPResponse(OCSPResponse::SUCCESSFUL);

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $mockCertificate = new class extends X509Certificate {
            // 此方法不需要重写，使用父类的默认实现
        };

        $result = $response->verifySignature($mockCertificate);

        $this->assertIsBool($result);
        $this->assertTrue($result);
    }
}
