<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSCertRevocation\RevocationPolicy;

/**
 * @internal
 */
#[CoversClass(RevocationPolicy::class)]
final class RevocationPolicyTest extends AbstractEnumTestCase
{
    public function testPolicyValuesAreCorrect(): void
    {
        $this->assertEquals('soft_fail', RevocationPolicy::SOFT_FAIL->value);
        $this->assertEquals('hard_fail', RevocationPolicy::HARD_FAIL->value);
        $this->assertEquals('crl_only', RevocationPolicy::CRL_ONLY->value);
        $this->assertEquals('ocsp_only', RevocationPolicy::OCSP_ONLY->value);
        $this->assertEquals('ocsp_preferred', RevocationPolicy::OCSP_PREFERRED->value);
        $this->assertEquals('crl_preferred', RevocationPolicy::CRL_PREFERRED->value);
        $this->assertEquals('disabled', RevocationPolicy::DISABLED->value);
    }

    public function testPolicyEnumCanBeUsedInMatch(): void
    {
        // 测试所有策略的匹配
        $policies = [
            RevocationPolicy::SOFT_FAIL,
            RevocationPolicy::HARD_FAIL,
            RevocationPolicy::CRL_ONLY,
            RevocationPolicy::OCSP_ONLY,
            RevocationPolicy::OCSP_PREFERRED,
            RevocationPolicy::CRL_PREFERRED,
            RevocationPolicy::DISABLED,
        ];

        foreach ($policies as $policy) {
            $result = match ($policy) {
                RevocationPolicy::SOFT_FAIL => 'soft_fail',
                RevocationPolicy::HARD_FAIL => 'hard_fail',
                RevocationPolicy::CRL_ONLY => 'crl_only',
                RevocationPolicy::OCSP_ONLY => 'ocsp_only',
                RevocationPolicy::OCSP_PREFERRED => 'ocsp_preferred',
                RevocationPolicy::CRL_PREFERRED => 'crl_preferred',
                RevocationPolicy::DISABLED => 'disabled',
            };

            $this->assertEquals($policy->value, $result);
        }
    }

    public function testPolicyEnumCanBeComparedDirectly(): void
    {
        $policies = [
            RevocationPolicy::OCSP_PREFERRED,
            RevocationPolicy::CRL_ONLY,
            RevocationPolicy::SOFT_FAIL,
        ];

        // 测试同一个枚举值的相等性
        $this->assertSame($policies[0], RevocationPolicy::OCSP_PREFERRED);

        // 测试不同枚举值的不相等性
        $this->assertNotSame($policies[0], $policies[1]);
        $this->assertNotSame($policies[0], $policies[2]);
    }

    public function testToArrayReturnsCorrectFormat(): void
    {
        $policy = RevocationPolicy::SOFT_FAIL;
        $array = $policy->toArray();

        $this->assertIsArray($array);
        $this->assertArrayHasKey('value', $array);
        $this->assertArrayHasKey('label', $array);
        $this->assertEquals('soft_fail', $array['value']);
        $this->assertEquals('软失败', $array['label']);
    }

    public function testToArrayForAllPolicies(): void
    {
        $testCases = [
            [RevocationPolicy::SOFT_FAIL, ['value' => 'soft_fail', 'label' => '软失败']],
            [RevocationPolicy::HARD_FAIL, ['value' => 'hard_fail', 'label' => '硬失败']],
            [RevocationPolicy::CRL_ONLY, ['value' => 'crl_only', 'label' => '仅CRL']],
            [RevocationPolicy::OCSP_ONLY, ['value' => 'ocsp_only', 'label' => '仅OCSP']],
            [RevocationPolicy::OCSP_PREFERRED, ['value' => 'ocsp_preferred', 'label' => 'OCSP优先']],
            [RevocationPolicy::CRL_PREFERRED, ['value' => 'crl_preferred', 'label' => 'CRL优先']],
            [RevocationPolicy::DISABLED, ['value' => 'disabled', 'label' => '禁用']],
        ];

        foreach ($testCases as [$policy, $expected]) {
            $array = $policy->toArray();
            $this->assertEquals($expected, $array);
        }
    }

    public function testToSelectItemReturnsCorrectFormat(): void
    {
        $policy = RevocationPolicy::OCSP_PREFERRED;
        $selectItem = $policy->toSelectItem();

        $this->assertIsArray($selectItem);
        $this->assertArrayHasKey('value', $selectItem);
        $this->assertArrayHasKey('text', $selectItem); // SelectTrait uses 'text' instead of 'label'
        $this->assertEquals('ocsp_preferred', $selectItem['value']);
        $this->assertEquals('OCSP优先', $selectItem['text']);
    }

    public function testToSelectItemForAllPolicies(): void
    {
        $testCases = [
            [RevocationPolicy::SOFT_FAIL, ['value' => 'soft_fail', 'text' => '软失败', 'label' => '软失败', 'name' => '软失败']],
            [RevocationPolicy::HARD_FAIL, ['value' => 'hard_fail', 'text' => '硬失败', 'label' => '硬失败', 'name' => '硬失败']],
            [RevocationPolicy::CRL_ONLY, ['value' => 'crl_only', 'text' => '仅CRL', 'label' => '仅CRL', 'name' => '仅CRL']],
            [RevocationPolicy::OCSP_ONLY, ['value' => 'ocsp_only', 'text' => '仅OCSP', 'label' => '仅OCSP', 'name' => '仅OCSP']],
            [RevocationPolicy::OCSP_PREFERRED, ['value' => 'ocsp_preferred', 'text' => 'OCSP优先', 'label' => 'OCSP优先', 'name' => 'OCSP优先']],
            [RevocationPolicy::CRL_PREFERRED, ['value' => 'crl_preferred', 'text' => 'CRL优先', 'label' => 'CRL优先', 'name' => 'CRL优先']],
            [RevocationPolicy::DISABLED, ['value' => 'disabled', 'text' => '禁用', 'label' => '禁用', 'name' => '禁用']],
        ];

        foreach ($testCases as [$policy, $expected]) {
            $selectItem = $policy->toSelectItem();
            $this->assertEquals($expected, $selectItem);
        }
    }
}
