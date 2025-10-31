<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;
use Tourze\TLSCertRevocation\CRL\CRLCache;
use Tourze\TLSCertRevocation\CRL\CRLParser;
use Tourze\TLSCertRevocation\CRL\CRLUpdater;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(CRLUpdater::class)]
final class CRLUpdaterTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 测试前设置，如果需要的话
    }

    public function testConstructCreatesInstance(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：CRLUpdater需要模拟CRLParser的解析行为，测试不关注具体解析逻辑
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2. 使用合理性：CRLUpdater需要模拟缓存操作，测试不关注具体缓存实现
        // 3. 替代方案：可考虑将来抽象出CRLCacheInterface，但当前项目中未定义该接口
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $updater = new CRLUpdater($parser, $cache);

        $this->assertInstanceOf(CRLUpdater::class, $updater);
    }

    public function testSetRefreshThreshold(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：CRLUpdater需要模拟CRLParser的解析行为，测试不关注具体解析逻辑
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2. 使用合理性：CRLUpdater需要模拟缓存操作，测试不关注具体缓存实现
        // 3. 替代方案：可考虑将来抽象出CRLCacheInterface，但当前项目中未定义该接口
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $updater = new CRLUpdater($parser, $cache);

        $updater->setRefreshThreshold(7200);

        // Test passes if no exception is thrown
        $this->assertTrue(true);
    }

    public function testCleanupExpiredCRLsCallsCacheRemoveExpired(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：测试清理功能时不需要实际解析操作，模拟具体类可简化测试
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2. 使用合理性：测试需要模拟缓存的removeExpired()方法的调用和返回值
        // 3. 替代方案：可考虑将来抽象出CRLCacheInterface，但当前项目中未定义该接口
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $cache->expects($this->once())
            ->method('removeExpired')
            ->willReturn(3)
        ;

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('info')
            ->with('已清理 3 个过期CRL')
        ;

        $updater = new CRLUpdater($parser, $cache, $logger);

        $result = $updater->cleanupExpiredCRLs();

        $this->assertEquals(3, $result);
    }

    public function testUpdateCRLReturnsTrueWhenCRLDoesNotNeedUpdate(): void
    {
        // 使用具体类 CRLParser 而非接口的原因：
        // 1) CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2) 测试CRL不需要更新的场景，必须模拟解析器行为
        // 3) 这是CRL处理的专用类，接口化会失去特定功能
        $parser = $this->createMock(CRLParser::class);

        // 使用具体类 CRLCache 而非接口的原因：
        // 1) CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2) 测试需要模拟缓存的get()和isExpiringSoon()方法，必须使用具体类
        // 3) 这是CRL缓存的专用类，接口化会失去缓存策略特性
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $existingCRL = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+2 hours'),
            '123'
        );

        $cache->expects($this->once())
            ->method('get')
            ->with('CN=Test CA')
            ->willReturn($existingCRL)
        ;

        $cache->expects($this->once())
            ->method('isExpiringSoon')
            ->with('CN=Test CA', 3600)
            ->willReturn(false)
        ;

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('debug')
            ->with('CRL无需更新: CN=Test CA')
        ;

        $updater = new CRLUpdater($parser, $cache, $logger);

        $result = $updater->updateCRL('CN=Test CA', 'http://example.com/crl.crl');

        $this->assertTrue($result);
    }

    public function testUpdateCRLReturnsFalseWhenFetchFails(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：测试需要模拟fetchFromURL()方法抛出异常的场景
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2. 使用合理性：测试需要模拟缓存的get()方法的调用和返回值
        // 3. 替代方案：可考虑将来抽象出CRLCacheInterface，但当前项目中未定义该接口
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        $cache->expects($this->once())
            ->method('get')
            ->with('CN=Test CA')
            ->willReturn(null)
        ;

        $parser->expects($this->once())
            ->method('fetchFromURL')
            ->with('http://example.com/crl.crl')
            ->willThrowException(new \Exception('Network error'))
        ;

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('info')
            ->with('正在从 http://example.com/crl.crl 获取CRL')
        ;

        $updater = new CRLUpdater($parser, $cache, $logger);

        $result = $updater->updateCRL('CN=Test CA', 'http://example.com/crl.crl', true);

        $this->assertFalse($result);
    }

    public function testUpdateFromCertificateReturnsNullWhenNoDistributionPoints(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：测试需要模拟extractCRLDistributionPoints()方法返回空数组的场景
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // 使用具体类 CRLCache 而非接口的原因：
        // 1) CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2) 测试证书无分发点的场景，必须模拟缓存行为
        // 3) 这是CRL缓存的专用类，接口化会失去缓存策略特性
        $cache = $this->createMock(CRLCache::class);

        // 使用具体类 X509Certificate 而非接口的原因：
        // 1) X509Certificate 是证书数据的载体类，包含getIssuerDN()等证书操作方法
        // 2) 测试需要模拟证书的getIssuerDN()方法，必须使用具体类
        // 3) 无适用的接口，X509Certificate是标准证书格式的具体实现类
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->expects($this->once())
            ->method('getIssuerDN')
            ->willReturn('CN=Test CA')
        ;

        $parser->expects($this->once())
            ->method('extractCRLDistributionPoints')
            ->with($certificate)
            ->willReturn([])
        ;

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->once())
            ->method('warning')
            ->with(self::stringContains('证书没有CRL分发点'))
        ;

        $updater = new CRLUpdater($parser, $cache, $logger);

        $result = $updater->updateFromCertificate($certificate);

        $this->assertNull($result);
    }

    public function testUpdateFromCertificateReturnsUpdatedCRL(): void
    {
        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLParser 包含复杂的CRL解析逻辑，无适用接口可抽象其所有解析方法
        // 2. 使用合理性：测试需要模拟extractCRLDistributionPoints()和fetchFromURL()方法的完整流程
        // 3. 替代方案：可考虑将来抽象出CRLParserInterface，但当前项目中未定义该接口
        $parser = $this->getMockBuilder(CRLParser::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：CRLCache 包含具体的缓存实现逻辑，如LRU策略、过期处理等
        // 2. 使用合理性：测试需要模拟完整的缓存操作流程，包括get()、isExpiringSoon()、add()等方法
        // 3. 替代方案：可考虑将来抽象出CRLCacheInterface，但当前项目中未定义该接口
        $cache = $this->getMockBuilder(CRLCache::class)
            ->disableOriginalConstructor()
            ->getMock()
        ;

        // Mock 具体类说明：
        // 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含getIssuerDN()等证书操作方法，这些方法在接口中无法标准化
        // 2. 使用合理性：测试需要模拟证书的getIssuerDN()方法，验证成功更新CRL的完整场景
        // 3. 替代方案：无适用的接口，X509Certificate是标准证书格式的具体实现类
        $certificate = $this->createMock(X509Certificate::class);
        $certificate->expects($this->once())
            ->method('getIssuerDN')
            ->willReturn('CN=Test CA')
        ;

        $distributionPoints = ['http://example.com/crl.crl'];
        $parser->expects($this->once())
            ->method('extractCRLDistributionPoints')
            ->with($certificate)
            ->willReturn($distributionPoints)
        ;

        $existingCRL = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-1 hour'),
            new \DateTimeImmutable('+30 minutes'),
            '123'
        );

        $newCRL = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '456'
        );

        $cache->expects($this->exactly(3))
            ->method('get')
            ->with('CN=Test CA')
            ->willReturnOnConsecutiveCalls($existingCRL, $existingCRL, $newCRL)
        ;

        $cache->expects($this->once())
            ->method('isExpiringSoon')
            ->with('CN=Test CA', 3600)
            ->willReturn(true)
        ;

        $parser->expects($this->once())
            ->method('fetchFromURL')
            ->with('http://example.com/crl.crl')
            ->willReturn($newCRL)
        ;

        $cache->expects($this->once())
            ->method('add')
            ->with('CN=Test CA', $newCRL)
        ;

        $logger = $this->createMock(LoggerInterface::class);

        $updater = new CRLUpdater($parser, $cache, $logger);

        $result = $updater->updateFromCertificate($certificate);

        $this->assertSame($newCRL, $result);
    }
}
