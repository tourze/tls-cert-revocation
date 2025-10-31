<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;
use Tourze\TLSCertRevocation\CRL\CRLEntry;

/**
 * @internal
 */
#[CoversClass(CertificateRevocationList::class)]
final class CertificateRevocationListTest extends TestCase
{
    public function testConstructCreatesInstance(): void
    {
        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 day'),
            '1'
        );

        $this->assertInstanceOf(CertificateRevocationList::class, $crl);
    }

    public function testAddRevokedCertificateStoresEntry(): void
    {
        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 day'),
            '1'
        );

        $entry = new CRLEntry(
            '12345',
            new \DateTimeImmutable(),
            CRLEntry::REASON_KEY_COMPROMISE
        );

        $result = $crl->addRevokedCertificate($entry);

        $this->assertSame($crl, $result);
        $this->assertTrue($crl->isRevoked('12345'));
        $this->assertSame($entry, $crl->getRevokedCertificate('12345'));
        $this->assertCount(1, $crl->getRevokedCertificates());
        $this->assertEquals(['12345' => $entry], $crl->getRevokedCertificates());
    }

    public function testAddRevokedCertificateOverwritesExistingEntry(): void
    {
        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 day'),
            '1'
        );

        $originalEntry = new CRLEntry(
            '12345',
            new \DateTimeImmutable('-1 hour'),
            CRLEntry::REASON_UNSPECIFIED
        );

        $newEntry = new CRLEntry(
            '12345',
            new \DateTimeImmutable(),
            CRLEntry::REASON_KEY_COMPROMISE
        );

        $crl->addRevokedCertificate($originalEntry);
        $crl->addRevokedCertificate($newEntry);

        $this->assertSame($newEntry, $crl->getRevokedCertificate('12345'));
        $this->assertCount(1, $crl->getRevokedCertificates());
    }

    public function testAddRevokedCertificateAllowsMultipleEntries(): void
    {
        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 day'),
            '1'
        );

        $entry1 = new CRLEntry(
            '12345',
            new \DateTimeImmutable(),
            CRLEntry::REASON_KEY_COMPROMISE
        );

        $entry2 = new CRLEntry(
            '67890',
            new \DateTimeImmutable(),
            CRLEntry::REASON_SUPERSEDED
        );

        $crl->addRevokedCertificate($entry1);
        $crl->addRevokedCertificate($entry2);

        $this->assertCount(2, $crl->getRevokedCertificates());
        $this->assertTrue($crl->isRevoked('12345'));
        $this->assertTrue($crl->isRevoked('67890'));
        $this->assertFalse($crl->isRevoked('99999'));
        $this->assertSame($entry1, $crl->getRevokedCertificate('12345'));
        $this->assertSame($entry2, $crl->getRevokedCertificate('67890'));
    }
}
