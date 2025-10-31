<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\Tests\OCSP;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCertRevocation\OCSP\OCSPResponse;
use Tourze\TLSCertRevocation\OCSP\OCSPResponseParser;

/**
 * @internal
 */
#[CoversClass(OCSPResponseParser::class)]
final class OCSPResponseParserTest extends TestCase
{
    public function testConstructCreatesInstance(): void
    {
        $parser = new OCSPResponseParser('test data');

        $this->assertInstanceOf(OCSPResponseParser::class, $parser);
    }

    public function testParse(): void
    {
        $parser = new OCSPResponseParser('valid-der-data');

        $result = $parser->parse();

        $this->assertIsArray($result);
        $this->assertArrayHasKey('responseStatus', $result);
        $this->assertArrayHasKey('responseType', $result);
        $this->assertArrayHasKey('certStatus', $result);
    }

    public function testParseResponseStatus(): void
    {
        $parser = new OCSPResponseParser('valid-der-data');

        $status = $parser->parseResponseStatus();

        $this->assertIsInt($status);
        $this->assertEquals(OCSPResponse::SUCCESSFUL, $status);
    }
}
