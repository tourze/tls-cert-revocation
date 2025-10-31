<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CRLParser;
use Tourze\TLSCertRevocation\Exception\CRLException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(CRLParser::class)]
final class CRLParserTest extends TestCase
{
    private CRLParser $parser;

    protected function setUp(): void
    {
        parent::setUp();

        $this->parser = new CRLParser();
    }

    public function testConstructCreatesInstance(): void
    {
        $parser = new CRLParser();

        $this->assertInstanceOf(CRLParser::class, $parser);
    }

    public function testParsePEMWithInvalidDataThrowsException(): void
    {
        $invalidPemData = 'invalid pem data';

        $this->expectException(CRLException::class);

        $this->parser->parsePEM($invalidPemData);
    }

    public function testParseDERWithInvalidDataThrowsException(): void
    {
        $invalidDerData = 'invalid der data';

        $this->expectException(CRLException::class);

        $this->parser->parseDER($invalidDerData);
    }

    public function testFetchFromURLWithInvalidURLThrowsException(): void
    {
        $invalidUrl = 'http://invalid-url-that-does-not-exist.example';

        $this->expectException(CRLException::class);

        $this->parser->fetchFromURL($invalidUrl);
    }

    public function testExtractCRLDistributionPointsReturnsExtensionData(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含getExtension()等证书操作方法，这些方法在接口中无法标准化
        // 2. 使用合理性：测试需要模拟证书扩展信息的获取，必须调用具体的getExtension()方法
        // 3. 替代方案：无适用的接口，X509Certificate是标准证书格式的具体实现类
        $mockCertificate = $this->getMockBuilder(X509Certificate::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $expectedDistributionPoints = ['http://crl.example.com/ca.crl'];
        $mockCertificate->method('getExtension')
            ->with('cRLDistributionPoints')
            ->willReturn($expectedDistributionPoints)
        ;

        $result = $this->parser->extractCRLDistributionPoints($mockCertificate);

        $this->assertEquals($expectedDistributionPoints, $result);
    }

    public function testExtractCRLDistributionPointsWithNullExtensionReturnsEmptyArray(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含getExtension()等证书操作方法，这些方法在接口中无法标准化
        // 2. 使用合理性：测试需要模拟证书扩展信息返回null的场景，必须调用具体的getExtension()方法
        // 3. 替代方案：无适用的接口，X509Certificate是标准证书格式的具体实现类
        $mockCertificate = $this->getMockBuilder(X509Certificate::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $mockCertificate->method('getExtension')
            ->with('cRLDistributionPoints')
            ->willReturn(null)
        ;

        $result = $this->parser->extractCRLDistributionPoints($mockCertificate);

        $this->assertEquals([], $result);
    }
}
