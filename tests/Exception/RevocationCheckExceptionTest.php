<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSCertRevocation\Exception\RevocationCheckException;

/**
 * @internal
 */
#[CoversClass(RevocationCheckException::class)]
final class RevocationCheckExceptionTest extends AbstractExceptionTestCase
{
    public function testExtendsRuntimeException(): void
    {
        $exception = new RevocationCheckException('Test message');

        $this->assertInstanceOf(\RuntimeException::class, $exception);
    }

    public function testConstructor(): void
    {
        $exception = new RevocationCheckException('Test message', 100);

        $this->assertSame('Test message', $exception->getMessage());
        $this->assertSame(100, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testConstructorWithPrevious(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new RevocationCheckException('Test message', 100, $previous);

        $this->assertSame('Test message', $exception->getMessage());
        $this->assertSame(100, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    public function testConstructorWithDefaults(): void
    {
        $exception = new RevocationCheckException();

        $this->assertSame('', $exception->getMessage());
        $this->assertSame(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    public function testCanBeCaught(): void
    {
        $this->expectException(RevocationCheckException::class);
        $this->expectExceptionMessage('Test exception');

        throw new RevocationCheckException('Test exception');
    }

    public function testCanBeCaughtAsRuntimeException(): void
    {
        $this->expectException(\RuntimeException::class);

        throw new RevocationCheckException('Test exception');
    }
}
