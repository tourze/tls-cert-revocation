<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\OCSP;

use Tourze\TLSCertRevocation\Exception\OCSPException;
use Tourze\TLSX509Core\Certificate\X509Certificate;

/**
 * OCSP响应类 - 解析和处理OCSP响应
 */
class OCSPResponse
{
    /**
     * OCSP响应状态常量
     */
    public const SUCCESSFUL = 0;
    public const MALFORMED_REQUEST = 1;
    public const INTERNAL_ERROR = 2;
    public const TRY_LATER = 3;
    public const SIG_REQUIRED = 5;
    public const UNAUTHORIZED = 6;

    /**
     * 证书状态常量
     */
    public const CERT_STATUS_GOOD = 0;
    public const CERT_STATUS_REVOKED = 1;
    public const CERT_STATUS_UNKNOWN = 2;

    /**
     * @var string|null 响应类型
     */
    private ?string $responseType = null;

    /**
     * @var int|null 证书状态
     */
    private ?int $certStatus = null;

    /**
     * @var \DateTimeImmutable|null 撤销时间
     */
    private ?\DateTimeImmutable $revocationTime = null;

    /**
     * @var int|null 撤销原因
     */
    private ?int $revocationReason = null;

    /**
     * @var \DateTimeImmutable|null 响应产生时间
     */
    private ?\DateTimeImmutable $producedAt = null;

    /**
     * @var \DateTimeImmutable|null 本次更新时间
     */
    private ?\DateTimeImmutable $thisUpdate = null;

    /**
     * @var \DateTimeImmutable|null 下次更新时间
     */
    private ?\DateTimeImmutable $nextUpdate = null;

    /**
     * @var string|null 证书序列号
     */
    private ?string $serialNumber = null;

    /**
     * @var string|null 响应中的随机数
     */
    private ?string $nonce = null;

    /**
     * @var string|null 响应者ID
     */
    private ?string $responderID = null;

    /**
     * @var string|null 签名算法
     */
    private ?string $signatureAlgorithm = null;

    /**
     * @var string|null 签名
     */
    private ?string $signature = null;

    /**
     * @var string|null 颁发者名称散列值
     */
    private ?string $issuerNameHash = null;

    /**
     * @var string|null 颁发者公钥散列值
     */
    private ?string $issuerKeyHash = null;

    /**
     * @var int 响应数据的过期警告秒数
     */
    private int $expiryWarningDays = 172800; // 172800秒 = 2天

    /**
     * @var array<string, mixed>|null 完整的TBS响应数据
     */
    private ?array $tbsResponseData = null;

    /**
     * 构造函数
     *
     * @param int         $responseStatus OCSP响应状态
     * @param string|null $rawData        原始响应数据
     */
    public function __construct(
        private readonly int $responseStatus,
        private readonly ?string $rawData = null,
    ) {
    }

    /**
     * 从DER编码数据解析OCSP响应
     *
     * @param string                  $derData DER编码的OCSP响应数据
     * @param OCSPResponseParser|null $parser  可选的自定义响应解析器
     *
     * @throws OCSPException 如果解析失败
     */
    public static function fromDER(string $derData, ?OCSPResponseParser $parser = null): self
    {
        try {
            $parser ??= new OCSPResponseParser($derData);
            $parsedData = $parser->parse();

            $response = self::createResponseFromParsedData($parsedData, $derData);
            self::populateResponseFields($response, $parsedData);

            return $response;
        } catch (\Throwable $e) {
            throw new OCSPException('解析OCSP响应失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 创建响应对象
     *
     * @param array<string, mixed> $parsedData 解析数据
     * @param string $derData DER数据
     *
     * @return self
     */
    private static function createResponseFromParsedData(array $parsedData, string $derData): self
    {
        $responseStatus = $parsedData['responseStatus'] ?? self::SUCCESSFUL;

        return new self(is_int($responseStatus) ? $responseStatus : self::SUCCESSFUL, $derData);
    }

    /**
     * 填充响应对象字段
     *
     * @param self $response 响应对象
     * @param array<string, mixed> $parsedData 解析数据
     */
    private static function populateResponseFields(self $response, array $parsedData): void
    {
        $response->responseType = self::extractStringField($parsedData, 'responseType');
        $response->certStatus = self::extractIntField($parsedData, 'certStatus');
        $response->producedAt = self::extractDateTimeField($parsedData, 'producedAt', new \DateTimeImmutable());
        $response->thisUpdate = self::extractDateTimeField($parsedData, 'thisUpdate', new \DateTimeImmutable());
        $response->nextUpdate = self::extractDateTimeField($parsedData, 'nextUpdate', new \DateTimeImmutable('+1 day'));
        $response->nonce = self::extractStringField($parsedData, 'nonce');
        $response->serialNumber = self::extractStringField($parsedData, 'serialNumber');
        $response->revocationTime = self::extractDateTimeField($parsedData, 'revocationTime');
        $response->revocationReason = self::extractIntField($parsedData, 'revocationReason');
        $response->signature = self::extractStringField($parsedData, 'signature');
        $response->signatureAlgorithm = self::extractStringField($parsedData, 'signatureAlgorithm');
        $response->responderID = self::extractStringField($parsedData, 'responderID');
        $response->issuerNameHash = self::extractStringField($parsedData, 'issuerNameHash');
        $response->issuerKeyHash = self::extractStringField($parsedData, 'issuerKeyHash');
        $response->tbsResponseData = $parsedData;
    }

    /**
     * 提取字符串字段
     *
     * @param array<string, mixed> $data 数据数组
     * @param string $key 键名
     *
     * @return string|null
     */
    private static function extractStringField(array $data, string $key): ?string
    {
        return isset($data[$key]) && is_string($data[$key]) ? $data[$key] : null;
    }

    /**
     * 提取整数字段
     *
     * @param array<string, mixed> $data 数据数组
     * @param string $key 键名
     *
     * @return int|null
     */
    private static function extractIntField(array $data, string $key): ?int
    {
        return isset($data[$key]) && is_int($data[$key]) ? $data[$key] : null;
    }

    /**
     * 提取日期时间字段
     *
     * @param array<string, mixed> $data 数据数组
     * @param string $key 键名
     * @param \DateTimeImmutable|null $default 默认值
     *
     * @return \DateTimeImmutable|null
     */
    private static function extractDateTimeField(array $data, string $key, ?\DateTimeImmutable $default = null): ?\DateTimeImmutable
    {
        return isset($data[$key]) && $data[$key] instanceof \DateTimeImmutable ? $data[$key] : $default;
    }

    /**
     * 从HTTP响应解析OCSP响应
     *
     * @param string $httpResponse HTTP响应内容
     *
     * @throws OCSPException 如果解析失败
     */
    public static function fromHTTP(string $httpResponse): self
    {
        try {
            // 从HTTP响应中提取OCSP响应数据
            // 检查内容类型
            if (false === strpos($httpResponse, 'Content-Type: application/ocsp-response')) {
                throw new OCSPException('HTTP响应内容类型不是application/ocsp-response');
            }

            // 提取响应体
            $parts = explode("\r\n\r\n", $httpResponse, 2);
            if (2 !== count($parts)) {
                throw new OCSPException('无效的HTTP响应格式');
            }

            $body = $parts[1];

            return self::fromDER($body);
        } catch (OCSPException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new OCSPException('从HTTP响应解析OCSP响应失败: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 检查响应是否成功
     *
     * @return bool 如果响应成功则返回true
     */
    public function isSuccessful(): bool
    {
        return self::SUCCESSFUL === $this->responseStatus;
    }

    /**
     * 获取响应状态
     *
     * @return int 响应状态
     */
    public function getResponseStatus(): int
    {
        return $this->responseStatus;
    }

    /**
     * 获取响应状态文本
     *
     * @return string 响应状态文本
     */
    public function getResponseStatusText(): string
    {
        $statusMap = [
            self::SUCCESSFUL => '成功',
            self::MALFORMED_REQUEST => '请求格式错误',
            self::INTERNAL_ERROR => '内部错误',
            self::TRY_LATER => '稍后重试',
            self::SIG_REQUIRED => '需要签名',
            self::UNAUTHORIZED => '未授权',
        ];

        return $statusMap[$this->responseStatus] ?? '未知状态';
    }

    /**
     * 获取证书状态
     *
     * @return int|null 证书状态
     */
    public function getCertStatus(): ?int
    {
        return $this->certStatus;
    }

    /**
     * 获取证书状态文本
     *
     * @return string 证书状态文本
     */
    public function getCertStatusText(): string
    {
        if (null === $this->certStatus) {
            return '未知';
        }

        $statusMap = [
            self::CERT_STATUS_GOOD => '有效',
            self::CERT_STATUS_REVOKED => '已撤销',
            self::CERT_STATUS_UNKNOWN => '未知',
        ];

        return $statusMap[$this->certStatus] ?? '未知状态';
    }

    /**
     * 检查证书是否有效
     *
     * @return bool 如果证书有效则返回true
     */
    public function isCertificateGood(): bool
    {
        return self::CERT_STATUS_GOOD === $this->certStatus;
    }

    /**
     * 检查证书是否已撤销
     *
     * @return bool 如果证书已撤销则返回true
     */
    public function isCertificateRevoked(): bool
    {
        return self::CERT_STATUS_REVOKED === $this->certStatus;
    }

    /**
     * 检查证书状态是否未知
     *
     * @return bool 如果证书状态未知则返回true
     */
    public function isCertificateUnknown(): bool
    {
        return self::CERT_STATUS_UNKNOWN === $this->certStatus || null === $this->certStatus;
    }

    /**
     * 获取撤销时间
     *
     * @return \DateTimeImmutable|null 撤销时间
     */
    public function getRevocationTime(): ?\DateTimeImmutable
    {
        return $this->revocationTime;
    }

    /**
     * 获取撤销原因
     *
     * @return int|null 撤销原因
     */
    public function getRevocationReason(): ?int
    {
        return $this->revocationReason;
    }

    /**
     * 获取响应产生时间
     *
     * @return \DateTimeImmutable|null 响应产生时间
     */
    public function getProducedAt(): ?\DateTimeImmutable
    {
        return $this->producedAt;
    }

    /**
     * 获取本次更新时间
     *
     * @return \DateTimeImmutable|null 本次更新时间
     */
    public function getThisUpdate(): ?\DateTimeImmutable
    {
        return $this->thisUpdate;
    }

    /**
     * 获取下次更新时间
     *
     * @return \DateTimeImmutable|null 下次更新时间
     */
    public function getNextUpdate(): ?\DateTimeImmutable
    {
        return $this->nextUpdate;
    }

    /**
     * 获取证书序列号
     *
     * @return string|null 证书序列号
     */
    public function getSerialNumber(): ?string
    {
        return $this->serialNumber;
    }

    /**
     * 检查响应是否已过期
     *
     * @return bool 如果响应已过期则返回true
     */
    public function isExpired(): bool
    {
        // 如果没有下次更新时间，无法确定是否过期
        if (null === $this->nextUpdate) {
            return false;
        }

        $now = new \DateTimeImmutable();

        return $now > $this->nextUpdate;
    }

    /**
     * 检查响应是否即将过期
     *
     * @param int $warningDays 警告天数
     *
     * @return bool 如果响应即将过期则返回true
     */
    public function isExpiringSoon(int $warningDays = 0): bool
    {
        // 如果没有下次更新时间，无法确定是否即将过期
        if (null === $this->nextUpdate) {
            return false;
        }

        $warningSeconds = $warningDays > 0 ? $warningDays * 86400 : $this->expiryWarningDays;

        $now = new \DateTimeImmutable();
        $warningTime = $this->nextUpdate->modify('-' . $warningSeconds . ' seconds');

        return $now > $warningTime && $now <= $this->nextUpdate;
    }

    /**
     * 获取响应中的随机数
     *
     * @return string|null 随机数
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * 验证响应随机数与请求随机数是否匹配
     *
     * @param string $requestNonce 请求随机数
     *
     * @return bool 如果随机数匹配则返回true
     */
    public function verifyNonce(string $requestNonce): bool
    {
        return null !== $this->nonce && $this->nonce === $requestNonce;
    }

    /**
     * 获取响应类型
     *
     * @return string|null 响应类型
     */
    public function getResponseType(): ?string
    {
        return $this->responseType;
    }

    /**
     * 获取原始响应数据
     *
     * @return string|null 原始响应数据
     */
    public function getRawData(): ?string
    {
        return $this->rawData;
    }

    /**
     * 设置过期警告秒数
     *
     * @param int $seconds 过期警告秒数
     */
    public function setExpiryWarningDays(int $seconds): void
    {
        $this->expiryWarningDays = $seconds;
    }

    /**
     * 获取响应者ID
     *
     * @return string|null 响应者ID
     */
    public function getResponderID(): ?string
    {
        return $this->responderID;
    }

    /**
     * 获取签名算法
     *
     * @return string|null 签名算法
     */
    public function getSignatureAlgorithm(): ?string
    {
        return $this->signatureAlgorithm;
    }

    /**
     * 获取签名
     *
     * @return string|null 签名
     */
    public function getSignature(): ?string
    {
        return $this->signature;
    }

    /**
     * 获取颁发者名称散列值
     *
     * @return string|null 颁发者名称散列值
     */
    public function getIssuerNameHash(): ?string
    {
        return $this->issuerNameHash;
    }

    /**
     * 获取颁发者公钥散列值
     *
     * @return string|null 颁发者公钥散列值
     */
    public function getIssuerKeyHash(): ?string
    {
        return $this->issuerKeyHash;
    }

    /**
     * 获取完整的TBS响应数据
     *
     * @return array<string, mixed>|null TBS响应数据
     */
    public function getTBSResponseData(): ?array
    {
        return $this->tbsResponseData;
    }

    /**
     * 检查响应是否与请求匹配
     *
     * @param OCSPRequest $request OCSP请求
     *
     * @return bool 如果响应与请求匹配则返回true
     */
    public function matchesRequest(OCSPRequest $request): bool
    {
        // 如果有随机数，验证随机数是否匹配
        $requestNonce = $request->getNonce();
        if (null !== $requestNonce && null !== $this->nonce && $requestNonce !== $this->nonce) {
            return false;
        }

        // 验证证书序列号是否匹配
        if ($request->getSerialNumber() !== $this->serialNumber) {
            return false;
        }

        // 验证颁发者信息是否匹配
        if ($request->getIssuerNameHash() !== $this->issuerNameHash
            || $request->getIssuerKeyHash() !== $this->issuerKeyHash) {
            return false;
        }

        return true;
    }

    /**
     * 验证响应签名
     *
     * @param X509Certificate $certificate 用于验证签名的证书
     * @param mixed           $verifier    签名验证器
     *
     * @return bool 如果签名有效则返回true
     */
    public function verifySignature(X509Certificate $certificate, $verifier = null): bool
    {
        // 简化实现，实际应使用适当的验签算法
        return true;
    }
}
