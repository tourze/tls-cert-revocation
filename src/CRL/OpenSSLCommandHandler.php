<?php

declare(strict_types=1);

namespace Tourze\TLSCertRevocation\CRL;

use Tourze\TLSCertRevocation\Exception\CRLException;

/**
 * OpenSSL命令处理器
 *
 * 专门处理与OpenSSL相关的命令执行和输出解析
 */
class OpenSSLCommandHandler
{
    /**
     * 执行OpenSSL命令解析DER数据
     */
    /**
     * @return array<string, mixed>
     */
    public function parseFromDER(string $derData): array
    {
        $tempFile = $this->createTempFile($derData);

        try {
            return $this->parseOpenSSLOutput($tempFile);
        } catch (CRLException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw CRLException::parseError('解析DER数据失败: ' . $e->getMessage());
        } finally {
            $this->cleanupTempFile($tempFile);
        }
    }

    /**
     * 创建临时文件
     */
    private function createTempFile(string $derData): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'crl');
        if (false === $tempFile) {
            throw CRLException::parseError('无法创建临时文件');
        }

        if (false === file_put_contents($tempFile, $derData)) {
            throw CRLException::parseError('无法写入临时文件');
        }

        return $tempFile;
    }

    /**
     * 清理临时文件
     */
    private function cleanupTempFile(string $tempFile): void
    {
        if (file_exists($tempFile)) {
            unlink($tempFile);
        }
    }

    /**
     * 解析OpenSSL输出
     */
    /**
     * @return array<string, mixed>
     */
    private function parseOpenSSLOutput(string $tempFile): array
    {
        $command = 'openssl crl -inform DER -in ' . escapeshellarg($tempFile) . ' -noout -text';
        $output = [];
        $exitCode = 0;
        exec($command, $output, $exitCode);

        if (0 !== $exitCode) {
            $this->handleOpenSSLError($command, $exitCode, $output, $tempFile);
        }

        $outputText = implode("\n", $output);

        return $this->extractCRLInfo($outputText);
    }

    /**
     * 处理OpenSSL命令错误
     */
    /**
     * @param array<string> $output
     */
    private function handleOpenSSLError(string $command, int $exitCode, array $output, string $tempFile): void
    {
        $errorMsg = '命令: ' . $command . ', 退出代码: ' . $exitCode;
        if ([] !== $output) {
            $errorMsg .= ', 输出: ' . implode("\n", $output);
        }

        // 尝试使用更简单的命令验证文件是否有效
        $testCommand = 'openssl crl -inform DER -in ' . escapeshellarg($tempFile) . ' -noout';
        $testOutput = [];
        $testExitCode = 0;
        exec($testCommand, $testOutput, $testExitCode);

        if (0 !== $testExitCode) {
            $errorMsg .= ', 文件验证失败: ' . implode("\n", $testOutput);
        }

        throw CRLException::parseError('OpenSSL命令执行失败: ' . $errorMsg);
    }

    /**
     * 从OpenSSL输出文本中提取CRL信息
     */
    /**
     * @return array<string, mixed>
     */
    private function extractCRLInfo(string $outputText): array
    {
        $crlInfo = [];

        // 提取基本信息
        $crlInfo = $this->extractBasicInfo($outputText);

        // 提取撤销证书列表
        $crlInfo['revoked'] = $this->extractRevokedCertificates($outputText);

        return $crlInfo;
    }

    /**
     * 提取CRL基本信息
     */
    /**
     * @return array<string, string>
     */
    private function extractBasicInfo(string $outputText): array
    {
        $crlInfo = [];
        $patterns = [
            'issuer' => '/Issuer:\s*(.+)$/m',
            'lastUpdate' => '/Last Update:\s*(.+)$/m',
            'nextUpdate' => '/Next Update:\s*(.+)$/m',
            'signatureAlgorithm' => '/Signature Algorithm:\s*(.+)$/m',
            'crlNumber' => '/CRL Number:\s*(.+)$/m',
        ];

        foreach ($patterns as $key => $pattern) {
            if (1 === preg_match($pattern, $outputText, $matches)) {
                $crlInfo[$key] = trim($matches[1]);
            }
        }

        return $crlInfo;
    }

    /**
     * 提取撤销证书列表
     */
    /**
     * @return array<array{serialNumber: string, revocationDate: string, reasonCode: string|null}>
     */
    private function extractRevokedCertificates(string $outputText): array
    {
        $revokedCerts = [];
        $pattern = '/Serial Number:\s*(.+?)[\r\n]+\s*Revocation Date:\s*(.+?)(?:[\r\n]+\s*CRL entry extensions:[^\r\n]*[\r\n]+\s*X509v3 CRL Reason Code:\s*(.+?))?(?=[\r\n]+\s*Serial Number:|$)/s';

        if (false !== preg_match_all($pattern, $outputText, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $match) {
                $revokedCerts[] = [
                    'serialNumber' => trim($match[1]),
                    'revocationDate' => trim($match[2]),
                    'reasonCode' => isset($match[3]) ? trim($match[3]) : null,
                ];
            }
        }

        return $revokedCerts;
    }
}
