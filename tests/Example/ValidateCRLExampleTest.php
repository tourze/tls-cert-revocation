<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Example;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\Example\ValidateCRLExample;
use Tourze\TLSCertRevocation\Validator\ValidationResult;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * @internal
 */
#[CoversClass(ValidateCRLExample::class)]
final class ValidateCRLExampleTest extends TestCase
{
    public function testConstructCreatesInstance(): void
    {
        $example = new ValidateCRLExample();

        $this->assertInstanceOf(ValidateCRLExample::class, $example);
    }

    public function testValidateCertificateRevocation(): void
    {
        $example = new ValidateCRLExample();
        // Mock 具体类说明：
        // 1. 为什么使用具体类：X509Certificate 是证书数据的载体类，包含证书解析和属性访问方法
        // 2. 使用合理性：测试需要模拟证书的getIssuerDN()方法，验证证书撤销检查流程
        // 3. 替代方案：无适用的接口，X509Certificate是X.509标准证书格式的具体实现类
        $mockCertificate = $this->createMock(X509Certificate::class);
        $mockCertificate->method('getIssuerDN')->willReturn('CN=Test CA');

        $result = $example->validateCertificateRevocation($mockCertificate);

        $this->assertInstanceOf(ValidationResult::class, $result);
    }

    public function testFormatValidationResult(): void
    {
        $example = new ValidateCRLExample();
        $result = new ValidationResult();
        $result->addSuccess('Test success message');
        $result->addError('Test error message');

        $formatted = $example->formatValidationResult($result);

        $this->assertIsString($formatted);
        $this->assertStringContainsString('证书撤销状态验证结果', $formatted);
        $this->assertStringContainsString('Test success message', $formatted);
        $this->assertStringContainsString('Test error message', $formatted);
    }

    public function testPrintCRLStats(): void
    {
        $example = new ValidateCRLExample();

        $stats = $example->printCRLStats();

        $this->assertIsString($stats);
        $this->assertStringContainsString('CRL缓存统计信息', $stats);
        $this->assertStringContainsString('缓存的CRL数量', $stats);
    }
}
