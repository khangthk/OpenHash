#pragma once

#include <QObject>
#include <openssl/evp.h>

enum class Hash
{
	crc32,
	crc32c,
#ifndef OPENSSL_NO_MD2
	md2,
#endif
#ifndef OPENSSL_NO_MD4
	md4,
#endif
#ifndef OPENSSL_NO_MD5
	md5,
#endif
	sha1,
	sha224,
	sha256,
	sha384,
	sha512,
	sha3_224,
	sha3_256,
	sha3_384,
	sha3_512,
	sha512_224,
	sha512_256,
	shake128,
	shake256,
#ifndef OPENSSL_NO_BLAKE2
	blake2b,
	blake2s,
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	whirlpool,
#endif
};

class OpenHash : public QObject
{
	Q_OBJECT
public:
	explicit OpenHash(const QString& file, QObject* parent = nullptr);

	QString crc32();
	QString crc32c();
#ifndef OPENSSL_NO_MD2
	QString md2();
#endif
#ifndef OPENSSL_NO_MD4
	QString md4();
#endif
#ifndef OPENSSL_NO_MD5
	QString md5();
#endif
	QString sha1();
	QString sha224();
	QString sha256();
	QString sha384();
	QString sha512();
	QString sha3_224();
	QString sha3_256();
	QString sha3_384();
	QString sha3_512();
	QString sha512_224();
	QString sha512_256();
	QString shake128();
	QString shake256();
#ifndef OPENSSL_NO_BLAKE2
	QString blake2b();
	QString blake2s();
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	QString whirlpool();
#endif
	QString Calculate(const EVP_MD* type);
	QList<QPair<Hash, QString>> Calculate(const QList<Hash>& hashs);
	static QString hashToString(const Hash& hash);

signals:
	void percent(const int value);
	void started();
	void finished();

private:
	QString m_file;
};


