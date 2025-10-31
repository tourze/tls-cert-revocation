<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\OCSP;

use Tourze\TLSCertRevocation\Exception\OCSPException;
use Tourze\TLSX509Core\Certificate\X509Certificate;
use Tourze\TLSX509Validation\Validator\ValidationResult;

/**
 * OCSP客户端类 - 用于发送OCSP请求和处理响应
 */
class OCSPClient
{
    /**
     * @var array<string, OCSPResponse> 响应缓存
     */
    private array $responseCache = [];

    /**
     * 构造函数
     *
     * @param int  $connectTimeout  连接超时时间（秒）
     * @param int  $responseTimeout 响应超时时间（秒）
     * @param bool $useNonce        是否使用随机数
     */
    public function __construct(
        private int $connectTimeout = 5,
        private int $responseTimeout = 10,
        private bool $useNonce = true,
    ) {
    }

    /**
     * 检查证书状态
     *
     * @param X509Certificate       $certificate       要检查的证书
     * @param X509Certificate       $issuerCertificate 颁发者证书
     * @param string|null           $ocspUrl           OCSP响应者URL，如果为null则从证书中获取
     * @param ValidationResult|null $result            验证结果，如果为null则创建新的
     *
     * @return ValidationResult 验证结果
     */
    public function check(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        ?string $ocspUrl = null,
        ?ValidationResult $result = null,
    ): ValidationResult {
        $result ??= new ValidationResult();

        try {
            $request = $this->createOCSPRequest($certificate, $issuerCertificate);

            // 检查缓存
            $cachedResponse = $this->checkCache($certificate, $issuerCertificate, $request, $result);
            if (null !== $cachedResponse) {
                return $cachedResponse;
            }

            // 获取OCSP URL
            $resolvedUrl = $this->resolveOCSPUrl($certificate, $ocspUrl, $result);
            if (null === $resolvedUrl) {
                return $result;
            }

            // 发送请求并验证响应
            return $this->sendAndValidateOCSPRequest($request, $resolvedUrl, $certificate, $issuerCertificate, $result);
        } catch (OCSPException $e) {
            $result->addError('OCSP检查失败: ' . $e->getMessage());

            return $result;
        } catch (\Throwable $e) {
            $result->addError('OCSP检查过程中发生未预期错误: ' . $e->getMessage());

            return $result;
        }
    }

    /**
     * 创建OCSP请求
     *
     * @param X509Certificate $certificate       要检查的证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     *
     * @return OCSPRequest OCSP请求
     *
     * @throws OCSPException 如果创建请求失败
     */
    protected function createOCSPRequest(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
    ): OCSPRequest {
        return OCSPRequest::fromCertificate(
            $certificate,
            $issuerCertificate,
            'sha1',
            $this->useNonce
        );
    }

    /**
     * 发送OCSP请求并获取响应
     *
     * @param string|OCSPRequest $url     OCSP响应者URL或OCSP请求对象
     * @param string|null        $request 编码的OCSP请求数据，如果第一个参数是OCSPRequest则忽略
     *
     * @return OCSPResponse 响应对象
     *
     * @throws OCSPException 如果请求失败
     */
    protected function sendRequest($url, ?string $request = null): OCSPResponse
    {
        try {
            // 如果第一个参数是OCSPRequest对象
            if ($url instanceof OCSPRequest) {
                $request = $url->encode();
                // 从OCSPRequest中获取URL（需要额外的参数）
                throw new OCSPException('使用OCSPRequest对象需要提供OCSP响应服务器URL');
            }
            if (!is_string($url)) {
                throw new OCSPException('URL必须是字符串类型');
            }

            if (null === $request) {
                throw new OCSPException('OCSP请求数据不能为空');
            }

            $responseData = $this->executeHttpRequest($url, $request);

            return $this->parseResponse($responseData);
        } catch (OCSPException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new OCSPException('发送OCSP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 执行HTTP请求
     *
     * @param string $url     请求URL
     * @param string $request 请求内容
     *
     * @return string 响应数据
     *
     * @throws OCSPException 如果请求失败
     */
    protected function executeHttpRequest(string $url, string $request): string
    {
        try {
            // 创建HTTP上下文
            $context = stream_context_create([
                'http' => [
                    'method' => 'POST',
                    'header' => 'Content-Type: application/ocsp-request' . "\r\n" .
                               'Content-Length: ' . strlen($request) . "\r\n" .
                               'Connection: close',
                    'content' => $request,
                    'timeout' => $this->responseTimeout,
                    'ignore_errors' => true,
                ],
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                    'capture_peer_cert' => true,
                    'timeout' => $this->connectTimeout,
                ],
            ]);

            // 发送请求
            $responseData = @file_get_contents($url, false, $context);

            if (false === $responseData) {
                throw new OCSPException('无法获取OCSP响应');
            }

            return $responseData;
        } catch (\Throwable $e) {
            throw new OCSPException('执行HTTP请求失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 解析OCSP响应
     *
     * @param string $responseData 响应数据
     *
     * @return OCSPResponse 响应对象
     *
     * @throws OCSPException 如果解析失败
     */
    protected function parseResponse(string $responseData): OCSPResponse
    {
        try {
            // 使用默认解析方法
            return OCSPResponse::fromDER($responseData);
        } catch (\Throwable $e) {
            throw new OCSPException('解析OCSP响应失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 验证OCSP响应
     *
     * @param OCSPResponse     $response OCSP响应
     * @param OCSPRequest      $request  原始OCSP请求
     * @param ValidationResult $result   验证结果
     *
     * @return ValidationResult 验证结果
     */
    protected function validateResponse(
        OCSPResponse $response,
        OCSPRequest $request,
        ValidationResult $result,
    ): ValidationResult {
        try {
            if (!$this->validateResponseStatus($response, $result)) {
                return $result;
            }

            $this->validateNonce($request, $response, $result);
            $this->validateResponseExpiry($response, $result);
            $this->validateCertificateStatus($response, $result);

            return $result;
        } catch (\Throwable $e) {
            $result->addError('验证OCSP响应失败: ' . $e->getMessage());

            return $result;
        }
    }

    /**
     * 生成缓存键
     *
     * @param X509Certificate $certificate       证书
     * @param X509Certificate $issuerCertificate 颁发者证书
     *
     * @return string 缓存键
     */
    private function getCacheKey(X509Certificate $certificate, X509Certificate $issuerCertificate): string
    {
        $serialNumber = $certificate->getSerialNumber();
        $issuerName = $issuerCertificate->getSubjectDN();

        return hash('sha256', $serialNumber . '|' . $issuerName);
    }

    /**
     * 设置连接超时时间
     *
     * @param int $timeout 超时时间（秒）
     */
    public function setConnectTimeout(int $timeout): void
    {
        $this->connectTimeout = $timeout;
    }

    /**
     * 设置响应超时时间
     *
     * @param int $timeout 超时时间（秒）
     */
    public function setResponseTimeout(int $timeout): void
    {
        $this->responseTimeout = $timeout;
    }

    /**
     * 设置是否使用随机数
     *
     * @param bool $useNonce 是否使用随机数
     */
    public function setUseNonce(bool $useNonce): void
    {
        $this->useNonce = $useNonce;
    }

    /**
     * 清除响应缓存
     */
    public function clearCache(): self
    {
        $this->responseCache = [];

        return $this;
    }

    /**
     * 从证书中获取OCSP URL
     *
     * @param X509Certificate $certificate 证书
     *
     * @return array<string> OCSP URL列表
     */
    protected function getOCSPURLs(X509Certificate $certificate): array
    {
        $urls = [];

        // 从AuthorityInfoAccess扩展中获取OCSP URL
        $aia = $certificate->getExtension('authorityInfoAccess');
        if (is_array($aia)) {
            foreach ($aia as $entry) {
                if (is_array($entry) && isset($entry['accessMethod']) && '1.3.6.1.5.5.7.48.1' === $entry['accessMethod']
                    && isset($entry['accessLocation']) && is_string($entry['accessLocation'])) {
                    $urls[] = $entry['accessLocation'];
                }
            }
        }

        return $urls;
    }

    /**
     * 检查证书是否被撤销
     *
     * @param X509Certificate $certificate 要检查的证书
     * @param X509Certificate $issuer      颁发者证书
     *
     * @return OCSPResponse OCSP响应
     *
     * @throws OCSPException 如果检查失败
     */
    public function checkCertificate(X509Certificate $certificate, X509Certificate $issuer): OCSPResponse
    {
        // 从证书中获取OCSP URL
        $ocspUrls = $this->getOCSPURLs($certificate);
        if ([] === $ocspUrls) {
            throw new OCSPException('证书中未找到OCSP响应者URL');
        }

        $ocspUrl = $ocspUrls[0]; // 使用第一个URL

        // 创建OCSP请求
        $request = $this->createOCSPRequest($certificate, $issuer);

        // 检查缓存
        $cacheKey = $this->getCacheKey($certificate, $issuer);
        if (isset($this->responseCache[$cacheKey])) {
            $cachedResponse = $this->responseCache[$cacheKey];

            // 检查缓存是否已过期
            if (!$cachedResponse->isExpired()) {
                return $cachedResponse;
            }

            // 缓存已过期，移除
            unset($this->responseCache[$cacheKey]);
        }

        // 发送请求获取响应
        $encodedRequest = $request->encode();
        $response = $this->sendRequest($ocspUrl, $encodedRequest);

        // 检查响应是否成功
        if (!$response->isSuccessful()) {
            throw new OCSPException('OCSP响应状态错误: ' . $response->getResponseStatusText());
        }

        // 缓存响应（如果成功且未过期）
        if (!$response->isExpired()) {
            $this->responseCache[$cacheKey] = $response;
        }

        return $response;
    }

    /**
     * 检查缓存并返回缓存的响应
     *
     * @param X509Certificate  $certificate       证书
     * @param X509Certificate  $issuerCertificate 颁发者证书
     * @param OCSPRequest      $request           OCSP请求
     * @param ValidationResult $result            验证结果
     *
     * @return ValidationResult|null 如果有有效缓存则返回验证结果，否则返回null
     */
    private function checkCache(
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        OCSPRequest $request,
        ValidationResult $result,
    ): ?ValidationResult {
        $cacheKey = $this->getCacheKey($certificate, $issuerCertificate);

        if (!isset($this->responseCache[$cacheKey])) {
            return null;
        }

        $cachedResponse = $this->responseCache[$cacheKey];

        if ($cachedResponse->isExpired()) {
            $result->addInfo('缓存的OCSP响应已过期，将获取新响应');
            unset($this->responseCache[$cacheKey]);

            return null;
        }

        $result->addInfo('使用缓存的OCSP响应');

        return $this->validateResponse($cachedResponse, $request, $result);
    }

    /**
     * 解析OCSP URL
     *
     * @param X509Certificate  $certificate 证书
     * @param string|null      $providedUrl 提供的URL
     * @param ValidationResult $result      验证结果
     *
     * @return string|null 解析后的URL，如果没有找到则返回null
     */
    private function resolveOCSPUrl(X509Certificate $certificate, ?string $providedUrl, ValidationResult $result): ?string
    {
        if (null !== $providedUrl) {
            return $providedUrl;
        }

        $ocspUrls = $this->getOCSPURLs($certificate);

        if ([] === $ocspUrls) {
            $result->addWarning('证书中未找到OCSP响应者URL');

            return null;
        }

        return $ocspUrls[0]; // 使用第一个URL
    }

    /**
     * 发送OCSP请求并验证响应
     *
     * @param OCSPRequest      $request           OCSP请求
     * @param string           $ocspUrl           OCSP URL
     * @param X509Certificate  $certificate       证书
     * @param X509Certificate  $issuerCertificate 颁发者证书
     * @param ValidationResult $result            验证结果
     *
     * @return ValidationResult 验证结果
     */
    private function sendAndValidateOCSPRequest(
        OCSPRequest $request,
        string $ocspUrl,
        X509Certificate $certificate,
        X509Certificate $issuerCertificate,
        ValidationResult $result,
    ): ValidationResult {
        $encodedRequest = $request->encode();
        $ocspResponse = $this->sendRequest($ocspUrl, $encodedRequest);

        $this->validateResponse($ocspResponse, $request, $result);

        // 缓存响应（如果成功）
        if ($ocspResponse->isSuccessful() && !$ocspResponse->isExpired()) {
            $cacheKey = $this->getCacheKey($certificate, $issuerCertificate);
            $this->responseCache[$cacheKey] = $ocspResponse;
        }

        return $result;
    }

    /**
     * 验证响应状态
     *
     * @param OCSPResponse     $response OCSP响应
     * @param ValidationResult $result   验证结果
     *
     * @return bool 如果状态有效返回true
     */
    private function validateResponseStatus(OCSPResponse $response, ValidationResult $result): bool
    {
        if (!$response->isSuccessful()) {
            $result->addError('OCSP响应状态错误: ' . $response->getResponseStatusText());

            return false;
        }

        return true;
    }

    /**
     * 验证随机数
     *
     * @param OCSPRequest      $request  OCSP请求
     * @param OCSPResponse     $response OCSP响应
     * @param ValidationResult $result   验证结果
     */
    private function validateNonce(OCSPRequest $request, OCSPResponse $response, ValidationResult $result): void
    {
        if (!$this->useNonce) {
            return;
        }

        $requestNonce = $request->getNonce();
        if (null === $requestNonce) {
            return;
        }

        $responseNonce = $response->getNonce();
        if (null === $responseNonce || $responseNonce !== $requestNonce) {
            $result->addWarning('OCSP响应随机数不匹配');
        }
    }

    /**
     * 验证响应有效期
     *
     * @param OCSPResponse     $response OCSP响应
     * @param ValidationResult $result   验证结果
     */
    private function validateResponseExpiry(OCSPResponse $response, ValidationResult $result): void
    {
        if ($response->isExpired()) {
            $result->addWarning('OCSP响应已过期');
        } elseif ($response->isExpiringSoon()) {
            $result->addInfo('OCSP响应即将过期');
        }
    }

    /**
     * 验证证书状态
     *
     * @param OCSPResponse     $response OCSP响应
     * @param ValidationResult $result   验证结果
     */
    private function validateCertificateStatus(OCSPResponse $response, ValidationResult $result): void
    {
        $certStatus = $response->getCertStatus();

        switch ($certStatus) {
            case OCSPResponse::CERT_STATUS_GOOD:
                $result->addSuccess('证书有效');
                break;
            case OCSPResponse::CERT_STATUS_REVOKED:
                $revocationTime = $response->getRevocationTime();
                $timeStr = null !== $revocationTime ? $revocationTime->format('Y-m-d H:i:s') : '未知';
                $result->addError('证书已被撤销，撤销时间: ' . $timeStr);
                break;
            default:
                $result->addWarning('证书状态未知');
                break;
        }
    }
}
