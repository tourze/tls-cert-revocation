# TLS Certificate Revocation

[![PHP](https://img.shields.io/badge/php-%5E8.1-blue)](https://www.php.net/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](#)

[English](README.md) | [中文](README.zh-CN.md)

A PHP library for handling TLS certificate revocation checks, providing comprehensive support for both 
CRL (Certificate Revocation List) and OCSP (Online Certificate Status Protocol) validation mechanisms.

## Table of Contents

- [Installation](#installation)
- [Requirements](#requirements)
- [Features](#features)
- [Quick Start](#quick-start)
- [Revocation Policies](#revocation-policies)
- [Advanced Usage](#advanced-usage)
- [Examples](#examples)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Related Packages](#related-packages)

## Installation

```bash
composer require tourze/tls-cert-revocation
```

## Requirements

- PHP 8.1 or higher
- OpenSSL extension
- curl extension (for OCSP requests)

## Features

- **CRL (Certificate Revocation List) Processing**
  - CRL parsing and validation
  - CRL caching for performance
  - Signature verification
  - Automatic CRL updates
  
- **OCSP (Online Certificate Status Protocol) Support**
  - OCSP request/response handling
  - OCSP stapling support
  - Real-time certificate status checking
  
- **Flexible Revocation Policies**
  - Multiple fallback strategies
  - Configurable failure handling
  - Support for network-unreliable environments
  
- **Caching and Performance**
  - Intelligent caching of revocation information
  - Configurable cache expiration
  - Network failure resilience

## Quick Start

### Basic Revocation Check

```php
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;
use Tourze\TLSX509Core\Certificate\X509Certificate;

// Load certificates
$certificate = X509Certificate::fromPEM(file_get_contents('cert.pem'));
$issuer = X509Certificate::fromPEM(file_get_contents('issuer.pem'));

// Create checker with OCSP preferred policy
$checker = new RevocationChecker(RevocationPolicy::OCSP_PREFERRED);

// Check if certificate is revoked
$isValid = $checker->check($certificate, $issuer);

if ($isValid) {
    echo "Certificate is valid and not revoked\n";
} else {
    echo "Certificate is revoked or status unknown\n";
}

// Get detailed check results
$status = $checker->getLastCheckStatus();
print_r($status);
```

### CRL-Only Validation

```php
use Tourze\TLSCertRevocation\CRL\CRLValidator;
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// Create CRL validator
$crlValidator = new CRLValidator();

// Create checker with CRL-only policy
$checker = new RevocationChecker(
    RevocationPolicy::CRL_ONLY,
    null,
    $crlValidator
);

$isValid = $checker->check($certificate, $issuer);
```

### OCSP-Only Validation

```php
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// Create OCSP client
$ocspClient = new OCSPClient();

// Create checker with OCSP-only policy
$checker = new RevocationChecker(
    RevocationPolicy::OCSP_ONLY,
    $ocspClient
);

$isValid = $checker->check($certificate, $issuer);
```

## Revocation Policies

The library supports various revocation checking policies:

| Policy | Description |
|--------|-------------|
| `SOFT_FAIL` | Continue validation even if revocation check fails (network errors) |
| `HARD_FAIL` | Treat any revocation check failure as invalid certificate |
| `CRL_ONLY` | Use only CRL for revocation checking |
| `OCSP_ONLY` | Use only OCSP for revocation checking |
| `OCSP_PREFERRED` | Try OCSP first, fallback to CRL if OCSP fails |
| `CRL_PREFERRED` | Try CRL first, fallback to OCSP if CRL fails |
| `DISABLED` | Skip all revocation checks |

## Advanced Usage

### Custom CRL Caching

```php
use Tourze\TLSCertRevocation\CRL\CRLCache;
use Tourze\TLSCertRevocation\CRL\CRLValidator;

// Create cache with custom TTL (1 hour)
$cache = new CRLCache(3600);

// Create validator with custom cache
$validator = new CRLValidator($cache);
```

### Handling Network Failures

```php
use Tourze\TLSCertRevocation\RevocationChecker;
use Tourze\TLSCertRevocation\RevocationPolicy;

// Use soft fail for unreliable networks
$checker = new RevocationChecker(RevocationPolicy::SOFT_FAIL);

$isValid = $checker->check($certificate, $issuer);
$status = $checker->getLastCheckStatus();

// Check what methods were attempted
foreach ($status['methods_tried'] as $method) {
    echo "Tried method: $method\n";
}

// Check for specific errors
if (isset($status['ocsp_error'])) {
    echo "OCSP Error: " . $status['ocsp_error'] . "\n";
}
if (isset($status['crl_error'])) {
    echo "CRL Error: " . $status['crl_error'] . "\n";
}
```

### Manual CRL Processing

```php
use Tourze\TLSCertRevocation\CRL\CRLParser;
use Tourze\TLSCertRevocation\CRL\CertificateRevocationList;

// Parse CRL from DER data
$crlData = file_get_contents('certificate.crl');
$parser = new CRLParser();
$crl = $parser->parse($crlData);

// Check if certificate is in CRL
$serialNumber = $certificate->getSerialNumber();
if ($crl->isRevoked($serialNumber)) {
    $entry = $crl->getRevokedCertificate($serialNumber);
    echo "Certificate revoked on: " . $entry->getRevocationDate()->format('Y-m-d H:i:s') . "\n";
    echo "Reason: " . $entry->getReasonCode() . "\n";
}
```

### Custom OCSP Requests

```php
use Tourze\TLSCertRevocation\OCSP\OCSPClient;
use Tourze\TLSCertRevocation\OCSP\OCSPRequest;

$client = new OCSPClient();

// Create custom OCSP request
$request = new OCSPRequest($certificate, $issuer);

// Send request to specific OCSP responder
$response = $client->sendRequest($request, 'http://ocsp.example.com');

// Check response
switch ($response->getCertStatus()) {
    case 0: // Good
        echo "Certificate is valid\n";
        break;
    case 1: // Revoked
        echo "Certificate is revoked\n";
        break;
    case 2: // Unknown
        echo "Certificate status unknown\n";
        break;
}
```

## Examples

See the `examples/` directory for complete working examples:

- `validate_crl.php` - Complete CRL validation example

## Testing

```bash
# Run all tests
./vendor/bin/phpunit packages/tls-cert-revocation/tests

# Run specific test
./vendor/bin/phpunit packages/tls-cert-revocation/tests/RevocationCheckerTest.php
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

MIT License. See [LICENSE](LICENSE) for details.

## Related Packages

- `tourze/tls-common` - Common TLS utilities
- `tourze/tls-crypto-asymmetric` - Asymmetric cryptography
- `tourze/tls-x509-core` - X.509 certificate handling
- `tourze/tls-x509-validation` - X.509 validation utilities