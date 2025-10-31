<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;
use Tourze\TLSCertRevocation\CRL\CRLCache;

/**
 * @internal
 */
#[CoversClass(CRLCache::class)]
final class CRLCacheTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 测试前设置，如果需要的话
    }

    public function testConstructCreatesInstance(): void
    {
        $cache = new CRLCache();

        $this->assertInstanceOf(CRLCache::class, $cache);
    }

    public function testCountReturnsZeroForNewCache(): void
    {
        $cache = new CRLCache();

        $this->assertEquals(0, $cache->count());
    }

    public function testGetIssuersReturnsEmptyArrayForNewCache(): void
    {
        $cache = new CRLCache();

        $this->assertEquals([], $cache->getIssuers());
    }

    public function testGetReturnsNullForNonExistentCRL(): void
    {
        $cache = new CRLCache();

        $result = $cache->get('CN=Non Existent CA');

        $this->assertNull($result);
    }

    public function testIsExpiringSoonReturnsTrueForNonExistentCRL(): void
    {
        $cache = new CRLCache();

        $result = $cache->isExpiringSoon('CN=Non Existent CA');

        $this->assertTrue($result);
    }

    public function testClearReturnsInstance(): void
    {
        $cache = new CRLCache();

        $result = $cache->clear();

        $this->assertSame($cache, $result);
    }

    public function testSetExpiringThreshold(): void
    {
        $cache = new CRLCache();

        $cache->setExpiringThreshold(7200);

        // Test passes if no exception is thrown
        $this->assertTrue(true);
    }

    public function testAddStoresCRLInCache(): void
    {
        $cache = new CRLCache();
        $issuerDN = 'CN=Test CA';
        $crl = new CertificateRevocationList(
            $issuerDN,
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '12345'
        );

        $result = $cache->add($issuerDN, $crl);

        $this->assertSame($cache, $result);
        $this->assertEquals(1, $cache->count());
        $this->assertSame($crl, $cache->get($issuerDN));
        $this->assertEquals([$issuerDN], $cache->getIssuers());
    }

    public function testAddRespectsMaxCacheSize(): void
    {
        $cache = new CRLCache(3600, 'PT1H', 2);

        $crl1 = new CertificateRevocationList(
            'CN=CA1',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '1'
        );
        $crl2 = new CertificateRevocationList(
            'CN=CA2',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '2'
        );
        $crl3 = new CertificateRevocationList(
            'CN=CA3',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '3'
        );

        $cache->add('CN=CA1', $crl1);
        $cache->add('CN=CA2', $crl2);
        $cache->add('CN=CA3', $crl3);

        $this->assertEquals(2, $cache->count());
        $this->assertNull($cache->get('CN=CA1')); // oldest should be removed
        $this->assertSame($crl2, $cache->get('CN=CA2'));
        $this->assertSame($crl3, $cache->get('CN=CA3'));
    }

    public function testRemoveExpiredRemovesExpiredCRLs(): void
    {
        $cache = new CRLCache();

        $expiredCRL = new CertificateRevocationList(
            'CN=Expired CA',
            new \DateTimeImmutable('-2 hours'),
            new \DateTimeImmutable('-1 hour'), // expired
            '1'
        );
        $validCRL = new CertificateRevocationList(
            'CN=Valid CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'), // not expired
            '2'
        );
        $neverExpiresCRL = new CertificateRevocationList(
            'CN=Never Expires CA',
            new \DateTimeImmutable(),
            null, // never expires
            '3'
        );

        $cache->add('CN=Expired CA', $expiredCRL);
        $cache->add('CN=Valid CA', $validCRL);
        $cache->add('CN=Never Expires CA', $neverExpiresCRL);

        $removedCount = $cache->removeExpired();

        $this->assertEquals(2, $removedCount); // both expired and null nextUpdate are removed
        $this->assertEquals(1, $cache->count());
        $this->assertNull($cache->get('CN=Expired CA'));
        $this->assertSame($validCRL, $cache->get('CN=Valid CA'));
        $this->assertNull($cache->get('CN=Never Expires CA')); // removed because nextUpdate is null
    }

    public function testRemoveExpiredReturnsZeroWhenNoCRLsExpired(): void
    {
        $cache = new CRLCache();

        $validCRL = new CertificateRevocationList(
            'CN=Valid CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '1'
        );

        $cache->add('CN=Valid CA', $validCRL);

        $removedCount = $cache->removeExpired();

        $this->assertEquals(0, $removedCount);
        $this->assertEquals(1, $cache->count());
        $this->assertSame($validCRL, $cache->get('CN=Valid CA'));
    }
}
