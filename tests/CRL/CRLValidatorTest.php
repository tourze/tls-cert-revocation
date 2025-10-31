<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\CRL;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;
use Tourze\TLSCertRevocation\CRL\CRLEntry;
use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\Crypto\SignatureVerifier;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(CRLValidator::class)]
final class CRLValidatorTest extends TestCase
{
    public function testConstructCreatesInstance(): void
    {
        $validator = new CRLValidator();

        $this->assertInstanceOf(CRLValidator::class, $validator);
    }

    public function testValidateWithValidCRL(): void
    {
        // 使用匿名类替代具体类Mock以符合静态分析规则
        $signatureVerifier = new class extends SignatureVerifier {
            private int $verifyCallCount = 0;

            public function verify(string $data, string $signature, string $publicKey, string $algorithm): bool
            {
                ++$this->verifyCallCount;

                return true;
            }

            public function getVerifyCallCount(): int
            {
                return $this->verifyCallCount;
            }
        };

        $validator = new CRLValidator($signatureVerifier);

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            private int $getPublicKeyCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Test CA';
            }

            public function getPublicKey(): string
            {
                ++$this->getPublicKeyCallCount;

                return 'mock-public-key';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }

            public function getPublicKeyCallCount(): int
            {
                return $this->getPublicKeyCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-1 hour'),
            new \DateTimeImmutable('+1 hour'),
            '123',
            'sha256WithRSAEncryption',
            'mock-signature',
            'mock-raw-data'
        );

        $result = $validator->validate($crl, $issuerCert);

        $this->assertTrue($result->isValid());
        $this->assertContains('CRL验证通过', $result->getSuccessMessages());
        $this->assertContains('CRL签名验证通过', $result->getInfoMessages());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $signatureVerifier->getVerifyCallCount());
        $this->assertEquals(1, $issuerCert->getSubjectDNCallCount());
        $this->assertEquals(1, $issuerCert->getPublicKeyCallCount());
    }

    public function testValidateWithMissingIssuerCertificate(): void
    {
        $validator = new CRLValidator();

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $result = $validator->validate($crl);

        $this->assertFalse($result->isValid());
        $this->assertContains('未提供CRL颁发者证书', $result->getErrors());
    }

    public function testValidateWithMismatchedIssuer(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Different CA';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $result = $validator->validate($crl, $issuerCert);

        $this->assertFalse($result->isValid());
        $this->assertContains('CRL颁发者与证书主题不匹配', $result->getErrors());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $issuerCert->getSubjectDNCallCount());
    }

    public function testValidateWithExpiredCRL(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Test CA';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-2 hours'),
            new \DateTimeImmutable('-1 hour'), // expired
            '123'
        );

        $result = $validator->validate($crl, $issuerCert);

        $this->assertTrue($result->isValid()); // expired CRL is still valid, just warned
        $this->assertContains('CRL已过期', $result->getWarnings());
        $this->assertContains('跳过CRL签名验证', $result->getWarnings());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $issuerCert->getSubjectDNCallCount());
    }

    public function testCheckRevocationWithRevokedCertificate(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $certificate = new class extends X509Certificate {
            private int $getIssuerDNCallCount = 0;

            private int $getSerialNumberCallCount = 0;

            public function getIssuerDN(bool $derFormat = false): string
            {
                ++$this->getIssuerDNCallCount;

                return 'CN=Test CA';
            }

            public function getSerialNumber(): string
            {
                ++$this->getSerialNumberCallCount;

                return '12345';
            }

            public function getIssuerDNCallCount(): int
            {
                return $this->getIssuerDNCallCount;
            }

            public function getSerialNumberCallCount(): int
            {
                return $this->getSerialNumberCallCount;
            }
        };

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Test CA';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-1 hour'),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $crl->setIssuerCertificate($issuerCert);

        $revokedEntry = new CRLEntry(
            '12345',
            new \DateTimeImmutable('-30 minutes'),
            CRLEntry::REASON_KEY_COMPROMISE
        );
        $crl->addRevokedCertificate($revokedEntry);

        $result = $validator->checkRevocation($certificate, $crl);

        $this->assertFalse($result->isValid());
        $this->assertCount(1, $result->getErrors());
        $errorMessage = $result->getErrors()[0];
        $this->assertStringContainsString('证书已被撤销', $errorMessage);
        $this->assertStringContainsString('密钥泄露', $errorMessage);

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $certificate->getIssuerDNCallCount());
        $this->assertEquals(1, $certificate->getSerialNumberCallCount());
        $this->assertGreaterThanOrEqual(1, $issuerCert->getSubjectDNCallCount());
    }

    public function testCheckRevocationWithValidCertificate(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $certificate = new class extends X509Certificate {
            private int $getIssuerDNCallCount = 0;

            private int $getSerialNumberCallCount = 0;

            public function getIssuerDN(bool $derFormat = false): string
            {
                ++$this->getIssuerDNCallCount;

                return 'CN=Test CA';
            }

            public function getSerialNumber(): string
            {
                ++$this->getSerialNumberCallCount;

                return '99999'; // not in CRL
            }

            public function getIssuerDNCallCount(): int
            {
                return $this->getIssuerDNCallCount;
            }

            public function getSerialNumberCallCount(): int
            {
                return $this->getSerialNumberCallCount;
            }
        };

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Test CA';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-1 hour'),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $crl->setIssuerCertificate($issuerCert);

        $result = $validator->checkRevocation($certificate, $crl);

        $this->assertTrue($result->isValid());
        $this->assertContains('证书未被撤销', $result->getInfoMessages());
        $this->assertContains('证书撤销检查通过', $result->getSuccessMessages());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $certificate->getIssuerDNCallCount());
        $this->assertEquals(1, $certificate->getSerialNumberCallCount());
        $this->assertGreaterThanOrEqual(1, $issuerCert->getSubjectDNCallCount());
    }

    public function testCheckRevocationWithMismatchedIssuer(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $certificate = new class extends X509Certificate {
            private int $getIssuerDNCallCount = 0;

            public function getIssuerDN(bool $derFormat = false): string
            {
                ++$this->getIssuerDNCallCount;

                return 'CN=Different CA';
            }

            public function getIssuerDNCallCount(): int
            {
                return $this->getIssuerDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable(),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $result = $validator->checkRevocation($certificate, $crl);

        $this->assertFalse($result->isValid());
        $this->assertContains('CRL颁发者与证书颁发者不匹配', $result->getErrors());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $certificate->getIssuerDNCallCount());
    }

    public function testCheckRevocationWithRemovedFromCRLCertificate(): void
    {
        $validator = new CRLValidator();

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $certificate = new class extends X509Certificate {
            private int $getIssuerDNCallCount = 0;

            private int $getSerialNumberCallCount = 0;

            public function getIssuerDN(bool $derFormat = false): string
            {
                ++$this->getIssuerDNCallCount;

                return 'CN=Test CA';
            }

            public function getSerialNumber(): string
            {
                ++$this->getSerialNumberCallCount;

                return '12345';
            }

            public function getIssuerDNCallCount(): int
            {
                return $this->getIssuerDNCallCount;
            }

            public function getSerialNumberCallCount(): int
            {
                return $this->getSerialNumberCallCount;
            }
        };

        // 使用匿名类替代具体类Mock以符合静态分析规则
        $issuerCert = new class extends X509Certificate {
            private int $getSubjectDNCallCount = 0;

            public function getSubjectDN(bool $derFormat = false): string
            {
                ++$this->getSubjectDNCallCount;

                return 'CN=Test CA';
            }

            public function getSubjectDNCallCount(): int
            {
                return $this->getSubjectDNCallCount;
            }
        };

        $crl = new CertificateRevocationList(
            'CN=Test CA',
            new \DateTimeImmutable('-1 hour'),
            new \DateTimeImmutable('+1 hour'),
            '123'
        );

        $crl->setIssuerCertificate($issuerCert);

        $removedEntry = new CRLEntry(
            '12345',
            new \DateTimeImmutable('-30 minutes'),
            CRLEntry::REASON_REMOVE_FROM_CRL // reason code 8
        );
        $crl->addRevokedCertificate($removedEntry);

        $result = $validator->checkRevocation($certificate, $crl);

        $this->assertTrue($result->isValid());
        $this->assertContains('证书已从CRL中移除', $result->getInfoMessages());
        $this->assertContains('证书撤销检查通过', $result->getSuccessMessages());

        // 验证方法调用次数，确保测试行为符合预期
        $this->assertEquals(1, $certificate->getIssuerDNCallCount());
        $this->assertEquals(1, $certificate->getSerialNumberCallCount());
        $this->assertGreaterThanOrEqual(1, $issuerCert->getSubjectDNCallCount());
    }
}
