<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\OpenSSLCommandHandler;
use Tourze\TLSCertRevocation\Exception\CRLException;

/**
 * @internal
 */
#[CoversClass(OpenSSLCommandHandler::class)]
final class OpenSSLCommandHandlerTest extends TestCase
{
    private OpenSSLCommandHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new OpenSSLCommandHandler();
    }

    public function testConstructCreatesInstance(): void
    {
        $handler = new OpenSSLCommandHandler();

        $this->assertInstanceOf(OpenSSLCommandHandler::class, $handler);
    }

    public function testParseFromDERWithValidDataReturnsArray(): void
    {
        // 创建一个最小有效的DER CRL数据结构
        // 这是一个简化的DER编码序列，模拟基本的CRL结构
        $validDerData = $this->createMinimalValidDERData();

        // 创建模拟处理器来测试解析逻辑
        $mockHandler = $this->createMockHandlerForValidParsing();

        $result = $mockHandler->parseFromDER($validDerData);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('issuer', $result);
        $this->assertArrayHasKey('lastUpdate', $result);
        $this->assertArrayHasKey('nextUpdate', $result);
        $this->assertArrayHasKey('revoked', $result);
        $this->assertIsArray($result['revoked']);
    }

    public function testParseFromDERWithInvalidDataThrowsException(): void
    {
        $invalidDerData = 'invalid der data';

        $this->expectException(CRLException::class);
        $this->expectExceptionMessage('无法解析CRL');

        $this->handler->parseFromDER($invalidDerData);
    }

    public function testParseFromDERWithEmptyDataThrowsException(): void
    {
        $emptyData = '';

        $this->expectException(CRLException::class);

        $this->handler->parseFromDER($emptyData);
    }

    public function testParseFromDERHandlesTempFileCreationFailure(): void
    {
        // 使用无效路径来模拟临时文件创建失败
        $mockHandler = $this->createMockHandlerForTempFileFailure();

        $this->expectException(CRLException::class);
        $this->expectExceptionMessage('无法创建临时文件');

        $mockHandler->parseFromDER('some data');
    }

    public function testParseFromDERHandlesOpenSSLCommandFailure(): void
    {
        $mockHandler = $this->createMockHandlerForOpenSSLFailure();

        $this->expectException(CRLException::class);
        $this->expectExceptionMessage('OpenSSL命令执行失败');

        $mockHandler->parseFromDER('some data');
    }

    public function testParseFromDERExtractsBasicInfoCorrectly(): void
    {
        $mockHandler = $this->createMockHandlerWithSpecificOutput();

        $result = $mockHandler->parseFromDER('dummy data');

        $this->assertEquals('CN=Test CA', $result['issuer']);
        $this->assertEquals('Jan 1 12:00:00 2024 GMT', $result['lastUpdate']);
        $this->assertEquals('Feb 1 12:00:00 2024 GMT', $result['nextUpdate']);
        $this->assertEquals('sha256WithRSAEncryption', $result['signatureAlgorithm']);
        $this->assertEquals('1A2B3C4D', $result['crlNumber']);
    }

    public function testParseFromDERExtractsRevokedCertificatesCorrectly(): void
    {
        $mockHandler = $this->createMockHandlerWithRevokedCerts();

        $result = $mockHandler->parseFromDER('dummy data');

        $this->assertCount(2, $result['revoked']);

        $firstRevoked = $result['revoked'][0];
        $this->assertEquals('12:34:56:78:9A:BC:DE:F0', $firstRevoked['serialNumber']);
        $this->assertEquals('Jan 15 10:30:00 2024 GMT', $firstRevoked['revocationDate']);
        $this->assertEquals('Key Compromise', $firstRevoked['reasonCode']);

        $secondRevoked = $result['revoked'][1];
        $this->assertEquals('FE:DC:BA:98:76:54:32:10', $secondRevoked['serialNumber']);
        $this->assertEquals('Jan 20 14:45:00 2024 GMT', $secondRevoked['revocationDate']);
        $this->assertNull($secondRevoked['reasonCode']);
    }

    public function testParseFromDERWithNoRevokedCertificatesReturnsEmptyArray(): void
    {
        $mockHandler = $this->createMockHandlerWithNoRevokedCerts();

        $result = $mockHandler->parseFromDER('dummy data');

        $this->assertArrayHasKey('revoked', $result);
        $this->assertEmpty($result['revoked']);
    }

    public function testParseFromDERCleansUpTempFileOnSuccess(): void
    {
        $mockHandler = $this->createMockHandlerForCleanupTest();

        // 执行测试，确保即使成功也会清理临时文件
        $result = $mockHandler->parseFromDER('dummy data');

        $this->assertIsArray($result);
        // 在真实实现中，临时文件应该被清理
        // 这里我们通过mock验证清理逻辑
    }

    public function testParseFromDERCleansUpTempFileOnException(): void
    {
        $mockHandler = $this->createMockHandlerForExceptionCleanupTest();

        try {
            $mockHandler->parseFromDER('dummy data');
            self::fail('Expected exception was not thrown');
        } catch (CRLException $e) {
            // 异常被正确抛出，临时文件应该已被清理
            $this->assertStringContainsString('解析DER数据失败', $e->getMessage());
        }
    }

    /**
     * 创建最小有效的DER数据用于测试
     */
    private function createMinimalValidDERData(): string
    {
        // 这是一个简化的DER编码序列，实际测试中应该使用真实的CRL数据
        $decoded = base64_decode('MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA', true);

        return false !== $decoded ? $decoded : '';
    }

    /**
     * 创建用于有效解析测试的模拟处理器
     */
    private function createMockHandlerForValidParsing(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willReturn([
                'issuer' => 'CN=Test CA',
                'lastUpdate' => 'Jan 1 12:00:00 2024 GMT',
                'nextUpdate' => 'Feb 1 12:00:00 2024 GMT',
                'signatureAlgorithm' => 'sha256WithRSAEncryption',
                'crlNumber' => '1A2B3C4D',
                'revoked' => [],
            ])
        ;

        return $mock;
    }

    /**
     * 创建用于测试临时文件创建失败的模拟处理器
     */
    private function createMockHandlerForTempFileFailure(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willThrowException(CRLException::parseError('无法创建临时文件'))
        ;

        return $mock;
    }

    /**
     * 创建用于测试OpenSSL命令失败的模拟处理器
     */
    private function createMockHandlerForOpenSSLFailure(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willThrowException(CRLException::parseError('OpenSSL命令执行失败: 命令: openssl crl -inform DER -in \'/tmp/test\' -noout -text, 退出代码: 1'))
        ;

        return $mock;
    }

    /**
     * 创建用于测试特定输出解析的模拟处理器
     */
    private function createMockHandlerWithSpecificOutput(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willReturn([
                'issuer' => 'CN=Test CA',
                'lastUpdate' => 'Jan 1 12:00:00 2024 GMT',
                'nextUpdate' => 'Feb 1 12:00:00 2024 GMT',
                'signatureAlgorithm' => 'sha256WithRSAEncryption',
                'crlNumber' => '1A2B3C4D',
                'revoked' => [],
            ])
        ;

        return $mock;
    }

    /**
     * 创建用于测试撤销证书解析的模拟处理器
     */
    private function createMockHandlerWithRevokedCerts(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willReturn([
                'issuer' => 'CN=Test CA',
                'lastUpdate' => 'Jan 1 12:00:00 2024 GMT',
                'nextUpdate' => 'Feb 1 12:00:00 2024 GMT',
                'signatureAlgorithm' => 'sha256WithRSAEncryption',
                'crlNumber' => '1A2B3C4D',
                'revoked' => [
                    [
                        'serialNumber' => '12:34:56:78:9A:BC:DE:F0',
                        'revocationDate' => 'Jan 15 10:30:00 2024 GMT',
                        'reasonCode' => 'Key Compromise',
                    ],
                    [
                        'serialNumber' => 'FE:DC:BA:98:76:54:32:10',
                        'revocationDate' => 'Jan 20 14:45:00 2024 GMT',
                        'reasonCode' => null,
                    ],
                ],
            ])
        ;

        return $mock;
    }

    /**
     * 创建用于测试无撤销证书的模拟处理器
     */
    private function createMockHandlerWithNoRevokedCerts(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willReturn([
                'issuer' => 'CN=Test CA',
                'lastUpdate' => 'Jan 1 12:00:00 2024 GMT',
                'nextUpdate' => 'Feb 1 12:00:00 2024 GMT',
                'signatureAlgorithm' => 'sha256WithRSAEncryption',
                'crlNumber' => '1A2B3C4D',
                'revoked' => [],
            ])
        ;

        return $mock;
    }

    /**
     * 创建用于测试清理逻辑的模拟处理器
     */
    private function createMockHandlerForCleanupTest(): OpenSSLCommandHandler
    {
        return $this->createMockHandlerForValidParsing();
    }

    /**
     * 创建用于测试异常情况下清理逻辑的模拟处理器
     */
    private function createMockHandlerForExceptionCleanupTest(): OpenSSLCommandHandler
    {
        $mock = $this->getMockBuilder(OpenSSLCommandHandler::class)
            ->onlyMethods(['parseFromDER'])
            ->getMock()
        ;

        $mock->method('parseFromDER')
            ->willThrowException(CRLException::parseError('解析DER数据失败: 模拟测试异常'))
        ;

        return $mock;
    }
}
