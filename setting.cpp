#include "setting.h"

#include <QSettings>

void Setting::saveHash(const Hash hash, const bool value)
{
	QSettings setting;
	switch (hash) {
	case Hash::crc32:
		setting.setValue("crc32", value);
		break;
	case Hash::crc32c:
		setting.setValue("crc32c", value);
		break;
#ifndef OPENSSL_NO_MD2
	case Hash::md2:
		setting.setValue("md2", value);
		break;
#endif
#ifndef OPENSSL_NO_MD4
	case Hash::md4:
		setting.setValue("md4", value);
		break;
#endif
#ifndef OPENSSL_NO_MD5
	case Hash::md5:
		setting.setValue("md5", value);
		break;
#endif
	case Hash::sha1:
		setting.setValue("sha1", value);
		break;
	case Hash::sha224:
		setting.setValue("sha224", value);
		break;
	case Hash::sha256:
		setting.setValue("sha256", value);
		break;
	case Hash::sha384:
		setting.setValue("sha384", value);
		break;
	case Hash::sha512:
		setting.setValue("sha512", value);
		break;
	case Hash::sha3_224:
		setting.setValue("sha3_224", value);
		break;
	case Hash::sha3_256:
		setting.setValue("sha3_256", value);
		break;
	case Hash::sha3_384:
		setting.setValue("sha3_384", value);
		break;
	case Hash::sha3_512:
		setting.setValue("sha3_512", value);
		break;
	case Hash::sha512_224:
		setting.setValue("sha512_224", value);
		break;
	case Hash::sha512_256:
		setting.setValue("sha512_256", value);
		break;
	case Hash::shake128:
		setting.setValue("shake128", value);
		break;
	case Hash::shake256:
		setting.setValue("shake256", value);
		break;
#ifndef OPENSSL_NO_BLAKE2
	case Hash::blake2b:
		setting.setValue("blake2b", value);
		break;
	case Hash::blake2s:
		setting.setValue("blake2s", value);
		break;
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	case Hash::whirlpool:
		setting.setValue("whirlpool", value);
		break;
#endif
	default:
		break;
	}
}

bool Setting::getHash(const Hash hash)
{
	QSettings setting;
	switch (hash) {
	case Hash::crc32:
		return setting.value("crc32", false).toBool();
	case Hash::crc32c:
		return setting.value("crc32c", false).toBool();
#ifndef OPENSSL_NO_MD2
	case Hash::md2:
		return setting.value("md2", false).toBool();
#endif
#ifndef OPENSSL_NO_MD4
	case Hash::md4:
		return setting.value("md4", false).toBool();
#endif
#ifndef OPENSSL_NO_MD5
	case Hash::md5:
		return setting.value("md5", false).toBool();
#endif
	case Hash::sha1:
		return setting.value("sha1", false).toBool();
	case Hash::sha224:
		return setting.value("sha224", false).toBool();
	case Hash::sha256:
		return setting.value("sha256", false).toBool();
	case Hash::sha384:
		return setting.value("sha384", false).toBool();
	case Hash::sha512:
		return setting.value("sha512", false).toBool();
	case Hash::sha3_224:
		return setting.value("sha3_224", false).toBool();
	case Hash::sha3_256:
		return setting.value("sha3_256", false).toBool();
	case Hash::sha3_384:
		return setting.value("sha3_384", false).toBool();
	case Hash::sha3_512:
		return setting.value("sha3_512", false).toBool();
	case Hash::sha512_224:
		return setting.value("sha512_224", false).toBool();
	case Hash::sha512_256:
		return setting.value("sha512_256", false).toBool();
	case Hash::shake128:
		return setting.value("shake128", false).toBool();
	case Hash::shake256:
		return setting.value("shake256", false).toBool();
#ifndef OPENSSL_NO_BLAKE2
	case Hash::blake2b:
		return setting.value("blake2b", false).toBool();
	case Hash::blake2s:
		return setting.value("blake2s", false).toBool();
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	case Hash::whirlpool:
		return setting.value("whirlpool", false).toBool();
#endif
	default:
		break;
	}
	return false;
}
