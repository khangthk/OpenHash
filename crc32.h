#pragma once
#include <stdint.h>

#define CRC32_DIGEST_LENGTH 4

#ifdef __cplusplus
extern "C" {
#endif

	typedef uint32_t CRC32_CTX;
	int CRC32_Init(CRC32_CTX* c);
	int CRC32_Update(CRC32_CTX* c, const void* data, size_t len);
	int CRC32_Final(unsigned char* md, CRC32_CTX* c);
	unsigned char* CRC32(const unsigned char* d, size_t n, unsigned char* md);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
