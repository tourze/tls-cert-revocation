<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CRLEntry;

/**
 * @internal
 */
#[CoversClass(CRLEntry::class)]
final class CRLEntryTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // 测试前设置，如果需要的话
    }

    public function testConstructSetsPropertiesCorrectly(): void
    {
        $serialNumber = '12345';
        $revocationDate = new \DateTimeImmutable('2023-12-01');
        $reasonCode = CRLEntry::REASON_KEY_COMPROMISE;
        $invalidityDate = new \DateTimeImmutable('2023-11-30');

        $entry = new CRLEntry($serialNumber, $revocationDate, $reasonCode, $invalidityDate);

        $this->assertEquals($serialNumber, $entry->getSerialNumber());
        $this->assertEquals($revocationDate, $entry->getRevocationDate());
        $this->assertEquals($reasonCode, $entry->getReasonCode());
        $this->assertEquals($reasonCode, $entry->getReason());
        $this->assertEquals($invalidityDate, $entry->getInvalidityDate());
    }

    public function testConstructWithOptionalParameters(): void
    {
        $serialNumber = '12345';
        $revocationDate = new \DateTimeImmutable('2023-12-01');

        $entry = new CRLEntry($serialNumber, $revocationDate);

        $this->assertEquals($serialNumber, $entry->getSerialNumber());
        $this->assertEquals($revocationDate, $entry->getRevocationDate());
        $this->assertNull($entry->getReasonCode());
        $this->assertNull($entry->getReason());
        $this->assertNull($entry->getInvalidityDate());
    }

    public function testGetReasonTextWithKnownReasonCode(): void
    {
        $entry = new CRLEntry('12345', new \DateTimeImmutable(), CRLEntry::REASON_KEY_COMPROMISE);

        $reasonText = $entry->getReasonText();

        $this->assertEquals('密钥泄露', $reasonText);
    }

    public function testGetReasonTextWithAllReasonCodes(): void
    {
        $reasonTests = [
            CRLEntry::REASON_UNSPECIFIED => '未指定',
            CRLEntry::REASON_KEY_COMPROMISE => '密钥泄露',
            CRLEntry::REASON_CA_COMPROMISE => 'CA证书泄露',
            CRLEntry::REASON_AFFILIATION_CHANGED => '附属关系变更',
            CRLEntry::REASON_SUPERSEDED => '被替代',
            CRLEntry::REASON_CESSATION_OF_OPERATION => '停止运营',
            CRLEntry::REASON_CERTIFICATE_HOLD => '证书暂停',
            CRLEntry::REASON_REMOVE_FROM_CRL => '从CRL移除',
            CRLEntry::REASON_PRIVILEGE_WITHDRAWN => '权限被撤销',
            CRLEntry::REASON_AA_COMPROMISE => 'AA泄露',
        ];

        foreach ($reasonTests as $reasonCode => $expectedText) {
            $entry = new CRLEntry('12345', new \DateTimeImmutable(), $reasonCode);
            $this->assertEquals($expectedText, $entry->getReasonText());
        }
    }

    public function testGetReasonTextWithNullReasonCode(): void
    {
        $entry = new CRLEntry('12345', new \DateTimeImmutable(), null);

        $reasonText = $entry->getReasonText();

        $this->assertEquals('未指定', $reasonText);
    }

    public function testGetReasonTextWithUnknownReasonCode(): void
    {
        $unknownReasonCode = 999;
        $entry = new CRLEntry('12345', new \DateTimeImmutable(), $unknownReasonCode);

        $reasonText = $entry->getReasonText();

        $this->assertEquals('未知(999)', $reasonText);
    }

    public function testReasonConstantsHaveCorrectValues(): void
    {
        $this->assertEquals(0, CRLEntry::REASON_UNSPECIFIED);
        $this->assertEquals(1, CRLEntry::REASON_KEY_COMPROMISE);
        $this->assertEquals(2, CRLEntry::REASON_CA_COMPROMISE);
        $this->assertEquals(3, CRLEntry::REASON_AFFILIATION_CHANGED);
        $this->assertEquals(4, CRLEntry::REASON_SUPERSEDED);
        $this->assertEquals(5, CRLEntry::REASON_CESSATION_OF_OPERATION);
        $this->assertEquals(6, CRLEntry::REASON_CERTIFICATE_HOLD);
        $this->assertEquals(8, CRLEntry::REASON_REMOVE_FROM_CRL);
        $this->assertEquals(9, CRLEntry::REASON_PRIVILEGE_WITHDRAWN);
        $this->assertEquals(10, CRLEntry::REASON_AA_COMPROMISE);
    }
}
