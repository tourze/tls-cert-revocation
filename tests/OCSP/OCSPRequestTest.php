<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\OCSP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\Exception\OCSPException;
use Tourze\TLSCertRevocation\OCSP\OCSPRequest;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(OCSPRequest::class)]
final class OCSPRequestTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // OCSPRequest 是一个数据模型类，需要构造函数参数，直接实例化是合理的
    }

    public function testConstructor(): void
    {
        $request = new OCSPRequest(
            '12345',
            'abcdef123456',
            'fedcba654321',
            'sha256',
            'nonce123'
        );

        $this->assertSame('12345', $request->getSerialNumber());
        $this->assertSame('abcdef123456', $request->getIssuerNameHash());
        $this->assertSame('fedcba654321', $request->getIssuerKeyHash());
        $this->assertSame('sha256', $request->getHashAlgorithm());
        $this->assertSame('nonce123', $request->getNonce());
    }

    public function testConstructorWithDefaults(): void
    {
        $request = new OCSPRequest(
            '12345',
            'abcdef123456',
            'fedcba654321'
        );

        $this->assertSame('12345', $request->getSerialNumber());
        $this->assertSame('abcdef123456', $request->getIssuerNameHash());
        $this->assertSame('fedcba654321', $request->getIssuerKeyHash());
        $this->assertSame('sha1', $request->getHashAlgorithm());
        $this->assertNull($request->getNonce());
    }

    public function testFromCertificateFailsWithoutIssuerSubjectDN(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('');
        $issuerCertificate->method('getSubjectDN')
            ->willReturnOnConsecutiveCalls('', '')
        ;

        $this->expectException(OCSPException::class);
        $this->expectExceptionMessage('无法获取颁发者主题DN');

        OCSPRequest::fromCertificate($certificate, $issuerCertificate);
    }

    public function testFromCertificateFailsWithoutIssuerPublicKey(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('CN=Test Issuer');
        $issuerCertificate->method('getPublicKeyDER')->willReturn(null);
        $issuerCertificate->method('getPublicKey')->willReturn('');

        $this->expectException(OCSPException::class);
        $this->expectExceptionMessage('无法获取颁发者公钥DER编码');

        OCSPRequest::fromCertificate($certificate, $issuerCertificate);
    }

    public function testFromCertificateSuccess(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('CN=Test Issuer');
        $issuerCertificate->method('getPublicKeyDER')->willReturn('public-key-der');

        $request = OCSPRequest::fromCertificate($certificate, $issuerCertificate, 'sha256', false);

        $this->assertSame('12345', $request->getSerialNumber());
        $this->assertSame('sha256', $request->getHashAlgorithm());
        $this->assertNull($request->getNonce());
        $this->assertNotEmpty($request->getIssuerNameHash());
        $this->assertNotEmpty($request->getIssuerKeyHash());
    }

    public function testFromCertificateWithNonce(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('CN=Test Issuer');
        $issuerCertificate->method('getPublicKeyDER')->willReturn('public-key-der');

        $request = OCSPRequest::fromCertificate($certificate, $issuerCertificate, 'sha1', true);

        $this->assertNotNull($request->getNonce());
        $this->assertSame(32, strlen($request->getNonce())); // 16 bytes = 32 hex chars
    }

    public function testEncode(): void
    {
        $request = new OCSPRequest(
            '12345',
            'abcdef123456',
            'fedcba654321'
        );

        $encoded = $request->encode();
        $this->assertNotEmpty($encoded);

        // 第二次调用应该返回缓存的值
        $encoded2 = $request->encode();
        $this->assertSame($encoded, $encoded2);
    }

    public function testEncodeForHTTP(): void
    {
        $request = new OCSPRequest(
            '12345',
            'abcdef123456',
            'fedcba654321'
        );

        $encoded = $request->encodeForHTTP();
        $this->assertNotEmpty($encoded);

        // 确保是有效的base64
        $decoded = base64_decode($encoded, true);
        $this->assertNotFalse($decoded);
    }

    public function testGetRequestURL(): void
    {
        $request = new OCSPRequest(
            '12345',
            'abcdef123456',
            'fedcba654321'
        );

        $url = $request->getRequestURL('http://ocsp.example.com');
        $this->assertStringStartsWith('http://ocsp.example.com/', $url);

        $url2 = $request->getRequestURL('http://ocsp.example.com/');
        $this->assertStringStartsWith('http://ocsp.example.com/', $url2);
        // 检查路径部分没有双斜杠（忽略协议部分的 //）
        $pathPart = str_replace('http://', '', $url2);
        $this->assertStringNotContainsString('//', $pathPart, 'URL path should not contain double slashes');
    }

    public function testGenerateWithOpenSSL(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('CN=Test Issuer');
        $issuerCertificate->method('getPublicKeyDER')->willReturn('public-key-der');

        $request = OCSPRequest::generateWithOpenSSL($certificate, $issuerCertificate);

        $this->assertInstanceOf(OCSPRequest::class, $request);
        $this->assertSame('12345', $request->getSerialNumber());
    }

    public function testGenerateWithOpenSSLHandlesException(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willThrowException(new \RuntimeException('Certificate error'));

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);

        $this->expectException(OCSPException::class);
        $this->expectExceptionMessage('创建OCSP请求失败: Certificate error');

        OCSPRequest::generateWithOpenSSL($certificate, $issuerCertificate);
    }

    public function testFromCertificateWithAlternativeSubjectDN(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('');
        $issuerCertificate->method('getSubjectDN')
            ->willReturnOnConsecutiveCalls('', 'Test Issuer')
        ;
        $issuerCertificate->method('getPublicKeyDER')->willReturn('public-key-der');

        $request = OCSPRequest::fromCertificate($certificate, $issuerCertificate);

        $this->assertSame('12345', $request->getSerialNumber());
        $this->assertNotEmpty($request->getIssuerNameHash());
        $this->assertNotEmpty($request->getIssuerKeyHash());
    }

    public function testFromCertificateWithAlternativePublicKey(): void
    {
        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->method('getSerialNumber')->willReturn('12345');

        // 必须使用具体类 X509Certificate 的理由：
        // 理由 1: OCSP 请求需要访问证书的特定方法（getSerialNumber、getSubjectDNDER、getPublicKeyDER）
        // 理由 2: 证书对象包含复杂的二进制数据结构，Mock 接口无法准确模拟这些数据的处理逻辑
        // 理由 3: 测试需要验证证书解析失败的边界情况，需要模拟具体的返回值和异常情况
        $issuerCertificate = $this->createMock(X509Certificate::class);
        $issuerCertificate->method('getSubjectDNDER')->willReturn('CN=Test Issuer');
        $issuerCertificate->method('getPublicKeyDER')->willReturn(null);
        $issuerCertificate->method('getPublicKey')->willReturn('public-key-pem');

        $request = OCSPRequest::fromCertificate($certificate, $issuerCertificate);

        $this->assertSame('12345', $request->getSerialNumber());
        $this->assertNotEmpty($request->getIssuerNameHash());
        $this->assertNotEmpty($request->getIssuerKeyHash());
    }
}
