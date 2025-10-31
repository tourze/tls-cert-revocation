<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\OCSP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\Exception\OCSPException;
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * @internal
 */
#[CoversClass(OCSPClient::class)]
final class OCSPClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    public function testConstructCreatesInstance(): void
    {
        $client = new OCSPClient();

        $this->assertInstanceOf(OCSPClient::class, $client);
    }

    public function testCheck(): void
    {
        $client = new OCSPClient();
        /*
         * Mock 具体类说明：
         * 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含证书解析和属性访问方法
         * 2. 使用合理性：测试需要模拟证书的各种属性获取方法，验证OCSP功能
         * 3. 替代方案：无适用的接口，X509Certificate是X.509标准证书格式的具体实现类
         */
        $mockCertificate = $this->createMock(X509Certificate::class);
        /*
         * Mock 具体类说明：
         * 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含证书解析和属性访问方法
         * 2. 使用合理性：测试需要模拟证书的各种属性获取方法，验证OCSP功能
         * 3. 替代方案：无适用的接口，X509Certificate是X.509标准证书格式的具体实现类
         */
        $mockIssuer = $this->createMock(X509Certificate::class);

        // Configure mock to return empty extension array (no OCSP URLs)
        $mockCertificate->method('getExtension')->willReturn([]);

        $result = $client->check($mockCertificate, $mockIssuer, 'http://ocsp.example.com');

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    public function testCheckCertificate(): void
    {
        $client = new OCSPClient();
        /*
         * Mock 具体类说明：
         * 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含证书解析和属性访问方法
         * 2. 使用合理性：测试需要模拟证书的各种属性获取方法，验证OCSP功能
         * 3. 替代方案：无适用的接口，X509Certificate是X.509标准证书格式的具体实现类
         */
        $mockCertificate = $this->createMock(X509Certificate::class);
        /*
         * Mock 具体类说明：
         * 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含证书解析和属性访问方法
         * 2. 使用合理性：测试需要模拟证书的各种属性获取方法，验证OCSP功能
         * 3. 替代方案：无适用的接口，X509Certificate是X.509标准证书格式的具体实现类
         */
        $mockIssuer = $this->createMock(X509Certificate::class);

        // Configure mock to return OCSP URL in AuthorityInfoAccess extension
        $mockCertificate->method('getExtension')->willReturn([
            [
                'accessMethod' => '1.3.6.1.5.5.7.48.1',
                'accessLocation' => 'http://ocsp.example.com',
            ],
        ]);
        $mockCertificate->method('getSerialNumber')->willReturn('123456');
        $mockIssuer->method('getSubjectDN')->willReturn('CN=Test CA');

        $this->expectException(OCSPException::class);

        $client->checkCertificate($mockCertificate, $mockIssuer);
    }

    public function testClearCache(): void
    {
        $client = new OCSPClient();

        $result = $client->clearCache();

        $this->assertSame($client, $result);
    }
}
