#pragma once
#include <stdint.h>

#define CRC32C_DIGEST_LENGTH 4

#ifdef __cplusplus
extern "C" {
#endif

	typedef uint32_t CRC32C_CTX;
	int CRC32C_Init(CRC32C_CTX* c);
	int CRC32C_Update(CRC32C_CTX* c, const void* data, size_t len);
	int CRC32C_Final(unsigned char* md, CRC32C_CTX* c);
	unsigned char* CRC32C(const unsigned char* d, size_t n, unsigned char* md);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
