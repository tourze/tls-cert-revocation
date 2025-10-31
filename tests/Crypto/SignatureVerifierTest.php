<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Crypto;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\Crypto\SignatureVerifier;
use Tourze\TLSCryptoAsymmetric\Signature\SignatureVerifier as BaseSignatureVerifier;

/**
 * @internal
 */
#[CoversClass(SignatureVerifier::class)]
final class SignatureVerifierTest extends TestCase
{
    public function testConstructCreatesInstance(): void
    {
        $verifier = new SignatureVerifier();

        $this->assertInstanceOf(SignatureVerifier::class, $verifier);
    }

    public function testVerifyWithValidSignature(): void
    {
        // 创建一个反射来替换私有属性
        $verifier = new SignatureVerifier();
        $reflection = new \ReflectionClass($verifier);
        $property = $reflection->getProperty('baseVerifier');
        $property->setAccessible(true);

        // Mock 具体类说明：
        // 1. 为什么使用具体类：BaseSignatureVerifier 封装了底层密码学签名验证逻辑，包含具体的RSA/EC算法实现
        // 2. 使用合理性：测试需要模拟底层签名验证器的verify()方法的不同返回结果，无需真实执行密码学运算
        // 3. 替代方案：可考虑抽象出SignatureVerifierInterface，但该类承担具体的密码学操作且为第三方依赖
        $mockBaseVerifier = $this->createMock(BaseSignatureVerifier::class);
        $mockBaseVerifier->expects($this->once())
            ->method('verify')
            ->with('test-data', 'test-signature', 'test-public-key', 'sha256WithRSAEncryption')
            ->willReturn(true)
        ;

        $property->setValue($verifier, $mockBaseVerifier);

        $result = $verifier->verify('test-data', 'test-signature', 'test-public-key', 'sha256WithRSAEncryption');

        $this->assertTrue($result);
    }

    public function testVerifyWithInvalidSignature(): void
    {
        $verifier = new SignatureVerifier();
        $reflection = new \ReflectionClass($verifier);
        $property = $reflection->getProperty('baseVerifier');
        $property->setAccessible(true);

        // Mock 具体类说明：
        // 1. 为什么使用具体类：BaseSignatureVerifier 封装了底层密码学签名验证逻辑，包含具体的RSA/EC算法实现
        // 2. 使用合理性：测试需要模拟底层签名验证器的verify()方法的不同返回结果，无需真实执行密码学运算
        // 3. 替代方案：可考虑抽象出SignatureVerifierInterface，但该类承担具体的密码学操作且为第三方依赖
        $mockBaseVerifier = $this->createMock(BaseSignatureVerifier::class);
        $mockBaseVerifier->expects($this->once())
            ->method('verify')
            ->with('test-data', 'invalid-signature', 'test-public-key', 'sha256WithRSAEncryption')
            ->willReturn(false)
        ;

        $property->setValue($verifier, $mockBaseVerifier);

        $result = $verifier->verify('test-data', 'invalid-signature', 'test-public-key', 'sha256WithRSAEncryption');

        $this->assertFalse($result);
    }

    public function testVerifyWithDifferentAlgorithms(): void
    {
        $verifier = new SignatureVerifier();
        $reflection = new \ReflectionClass($verifier);
        $property = $reflection->getProperty('baseVerifier');
        $property->setAccessible(true);

        // Mock 具体类说明：
        // 1. 为什么使用具体类：BaseSignatureVerifier 封装了底层密码学签名验证逻辑，包含具体的RSA/EC算法实现
        // 2. 使用合理性：测试需要模拟底层签名验证器的verify()方法的不同返回结果，无需真实执行密码学运算
        // 3. 替代方案：可考虑抽象出SignatureVerifierInterface，但该类承担具体的密码学操作且为第三方依赖
        $mockBaseVerifier = $this->createMock(BaseSignatureVerifier::class);
        $mockBaseVerifier->expects($this->exactly(3))
            ->method('verify')
            ->willReturnOnConsecutiveCalls(true, false, true)
        ;

        $property->setValue($verifier, $mockBaseVerifier);

        $this->assertTrue($verifier->verify('data1', 'sig1', 'key1', 'sha256WithRSAEncryption'));
        $this->assertFalse($verifier->verify('data2', 'sig2', 'key2', 'sha1WithRSAEncryption'));
        $this->assertTrue($verifier->verify('data3', 'sig3', 'key3', 'md5WithRSAEncryption'));
    }

    public function testVerifyPassesThroughAllParameters(): void
    {
        $verifier = new SignatureVerifier();
        $reflection = new \ReflectionClass($verifier);
        $property = $reflection->getProperty('baseVerifier');
        $property->setAccessible(true);

        // Mock 具体类说明：
        // 1. 为什么使用具体类：BaseSignatureVerifier 封装了底层密码学签名验证逻辑，包含具体的RSA/EC算法实现
        // 2. 使用合理性：测试需要模拟底层签名验证器的verify()方法的不同返回结果，无需真实执行密码学运算
        // 3. 替代方案：可考虑抽象出SignatureVerifierInterface，但该类承担具体的密码学操作且为第三方依赖
        $mockBaseVerifier = $this->createMock(BaseSignatureVerifier::class);

        $testData = 'test-certificate-data-' . uniqid();
        $testSignature = 'test-signature-' . uniqid();
        $testPublicKey = 'test-public-key-' . uniqid();
        $testAlgorithm = 'sha384WithRSAEncryption';

        $mockBaseVerifier->expects($this->once())
            ->method('verify')
            ->with(
                self::identicalTo($testData),
                self::identicalTo($testSignature),
                self::identicalTo($testPublicKey),
                self::identicalTo($testAlgorithm)
            )
            ->willReturn(true)
        ;

        $property->setValue($verifier, $mockBaseVerifier);

        $result = $verifier->verify($testData, $testSignature, $testPublicKey, $testAlgorithm);

        $this->assertTrue($result);
    }
}
