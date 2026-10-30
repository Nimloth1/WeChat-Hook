#pragma once
// 仅适配macOS离线SHA256调用；许可解析/绑定/消耗使用原始生产C++源码。
#include <CommonCrypto/CommonDigest.h>
using BCRYPT_ALG_HANDLE = void*;
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
inline int BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* algorithm, const wchar_t*, void*, int) {
    *algorithm = reinterpret_cast<void*>(1);
    return 0;
}
inline int BCryptHash(BCRYPT_ALG_HANDLE, void*, int, PUCHAR data, ULONG size, unsigned char* out, int) {
    return CC_SHA256(data, size, out) ? 0 : -1;
}
inline int BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, int) { return 0; }
