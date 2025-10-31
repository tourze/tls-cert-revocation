<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Validator;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\Validator\ValidationResult;

/**
 * @internal
 */
#[CoversClass(ValidationResult::class)]
final class ValidationResultTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // ValidationResult 是一个值对象类，需要构造函数参数，直接实例化是合理的
    }

    public function testConstructCreatesInstance(): void
    {
        $result = new ValidationResult(true);

        $this->assertInstanceOf(ValidationResult::class, $result);
        $this->assertTrue($result->isValid());
    }

    public function testAddErrorSetsValidToFalse(): void
    {
        $result = new ValidationResult(true);

        $returnValue = $result->addError('Test error message');

        $this->assertSame($result, $returnValue);
        $this->assertFalse($result->isValid());
        $this->assertEquals(['Test error message'], $result->getErrors());
    }

    public function testAddErrorAllowsMultipleErrors(): void
    {
        $result = new ValidationResult();

        $result->addError('First error');
        $result->addError('Second error');

        $this->assertFalse($result->isValid());
        $this->assertEquals(['First error', 'Second error'], $result->getErrors());
    }

    public function testAddInfoStoresMessage(): void
    {
        $result = new ValidationResult();

        $returnValue = $result->addInfo('Test info message');

        $this->assertSame($result, $returnValue);
        $this->assertTrue($result->isValid()); // info doesn't affect validity
        $this->assertEquals(['Test info message'], $result->getInfoMessages());
    }

    public function testAddInfoAllowsMultipleMessages(): void
    {
        $result = new ValidationResult();

        $result->addInfo('First info');
        $result->addInfo('Second info');

        $this->assertTrue($result->isValid());
        $this->assertEquals(['First info', 'Second info'], $result->getInfoMessages());
    }

    public function testAddSuccessStoresMessage(): void
    {
        $result = new ValidationResult();

        $returnValue = $result->addSuccess('Test success message');

        $this->assertSame($result, $returnValue);
        $this->assertTrue($result->isValid()); // success doesn't affect validity
        $this->assertEquals(['Test success message'], $result->getSuccessMessages());
    }

    public function testAddSuccessAllowsMultipleMessages(): void
    {
        $result = new ValidationResult();

        $result->addSuccess('First success');
        $result->addSuccess('Second success');

        $this->assertTrue($result->isValid());
        $this->assertEquals(['First success', 'Second success'], $result->getSuccessMessages());
    }

    public function testAddWarningStoresMessage(): void
    {
        $result = new ValidationResult();

        $returnValue = $result->addWarning('Test warning message');

        $this->assertSame($result, $returnValue);
        $this->assertTrue($result->isValid()); // warning doesn't affect validity
        $this->assertEquals(['Test warning message'], $result->getWarnings());
    }

    public function testAddWarningAllowsMultipleMessages(): void
    {
        $result = new ValidationResult();

        $result->addWarning('First warning');
        $result->addWarning('Second warning');

        $this->assertTrue($result->isValid());
        $this->assertEquals(['First warning', 'Second warning'], $result->getWarnings());
    }

    public function testMergesCombinesAllMessages(): void
    {
        $result1 = new ValidationResult();
        $result1->addError('Error 1');
        $result1->addWarning('Warning 1');
        $result1->addInfo('Info 1');
        $result1->addSuccess('Success 1');

        $result2 = new ValidationResult();
        $result2->addError('Error 2');
        $result2->addWarning('Warning 2');
        $result2->addInfo('Info 2');
        $result2->addSuccess('Success 2');

        $returnValue = $result1->merge($result2);

        $this->assertSame($result1, $returnValue);
        $this->assertFalse($result1->isValid()); // has errors from both
        $this->assertEquals(['Error 1', 'Error 2'], $result1->getErrors());
        $this->assertEquals(['Warning 1', 'Warning 2'], $result1->getWarnings());
        $this->assertEquals(['Info 1', 'Info 2'], $result1->getInfoMessages());
        $this->assertEquals(['Success 1', 'Success 2'], $result1->getSuccessMessages());
    }

    public function testMergeWithValidResults(): void
    {
        $result1 = new ValidationResult();
        $result1->addInfo('Info 1');
        $result1->addSuccess('Success 1');

        $result2 = new ValidationResult();
        $result2->addInfo('Info 2');
        $result2->addSuccess('Success 2');

        $result1->merge($result2);

        $this->assertTrue($result1->isValid()); // both were valid
        $this->assertEquals(['Info 1', 'Info 2'], $result1->getInfoMessages());
        $this->assertEquals(['Success 1', 'Success 2'], $result1->getSuccessMessages());
    }

    public function testMergeWithInvalidResults(): void
    {
        $result1 = new ValidationResult();
        $result1->addSuccess('Success 1');

        $result2 = new ValidationResult();
        $result2->addError('Error 2');

        $result1->merge($result2);

        $this->assertFalse($result1->isValid()); // result2 was invalid
        $this->assertEquals(['Error 2'], $result1->getErrors());
        $this->assertEquals(['Success 1'], $result1->getSuccessMessages());
    }
}
