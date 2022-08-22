#include "openhash.h"
#include "crc32.h"
#include "crc32c.h"
#include <openssl/evp.h>

#include <QDebug>
#include <QString>
#include <QList>
#include <QPair>
#include <QFile>

#define BUFFER_SIZE 1024*8

class Sentry
{
public:
	Sentry(OpenHash* pHash)
	{
		m_pHash = pHash;
		emit m_pHash->started();
		qDebug() << "started";
	}

	~Sentry()
	{
		emit m_pHash->finished();
		qDebug() << "finished";
	}

private:
	OpenHash* m_pHash;
};

OpenHash::OpenHash(const QString& file, QObject* parent) : QObject{ parent }, m_file(file)
{
}

QString OpenHash::crc32()
{
	Sentry sentry = Sentry(this);
	if (!m_file.isEmpty())
	{
		QFile file(m_file);
		if (!file.open(QIODevice::ReadOnly))
		{
			return QString();
		}

		CRC32_CTX crc32;
		CRC32_Init(&crc32);

		char buffer[BUFFER_SIZE];
		unsigned char digest[CRC32_DIGEST_LENGTH];
		int progress = 0;
		qint64 fsize = file.size();
		qint64 total = 0;
		while (!file.atEnd())
		{
			qint64 bytes = file.read(buffer, sizeof(buffer));
			total += bytes;
			CRC32_Update(&crc32, buffer, bytes);

			auto val = static_cast<int>((total * 1.0 / fsize) * 100 + 0.5);
			if (progress != val)
			{
				progress = val;
				emit percent(val);
			}
		}

		file.close();

		CRC32_Final(digest, &crc32);

		QString result;
		for (int i = 0; i < CRC32_DIGEST_LENGTH; ++i)
		{
			result += QString("%1").arg(digest[i], 2, 16, QChar('0')).toUpper();
		}
		return result;
	}

	return QString();
}

QString OpenHash::crc32c()
{
	Sentry sentry = Sentry(this);
	if (!m_file.isEmpty())
	{
		QFile file(m_file);
		if (!file.open(QIODevice::ReadOnly))
		{
			return QString();
		}

		CRC32C_CTX crc32c;
		CRC32C_Init(&crc32c);

		char buffer[BUFFER_SIZE];
		unsigned char digest[CRC32C_DIGEST_LENGTH];
		int progress = 0;
		qint64 fsize = file.size();
		qint64 total = 0;

		while (!file.atEnd())
		{
			size_t bytes = file.read(buffer, sizeof(buffer));
			total += bytes;
			CRC32C_Update(&crc32c, buffer, bytes);

			auto val = static_cast<int>((total * 1.0 / fsize) * 100 + 0.5);
			if (progress != val)
			{
				progress = val;
				emit percent(val);
			}
		}

		file.close();

		CRC32C_Final(digest, &crc32c);

		QString result;
		for (int i = 0; i < CRC32C_DIGEST_LENGTH; ++i)
		{
			result += QString("%1").arg(digest[i], 2, 16, QChar('0')).toUpper();
		}
		return result;
	}

	return QString();
}

#ifndef OPENSSL_NO_MD2
QString OpenHash::md2()
{
	return Calculate(EVP_md2());
}
#endif

#ifndef OPENSSL_NO_MD4
QString OpenHash::md4()
{
	return Calculate(EVP_md4());
}
#endif

#ifndef OPENSSL_NO_MD5
QString OpenHash::md5()
{
	return Calculate(EVP_md5());
}
#endif

QString OpenHash::sha1()
{
	return Calculate(EVP_sha1());
}

QString OpenHash::sha224()
{
	return Calculate(EVP_sha224());
}

QString OpenHash::sha256()
{
	return Calculate(EVP_sha256());
}

QString OpenHash::sha384()
{
	return Calculate(EVP_sha384());
}

QString OpenHash::sha512()
{
	return Calculate(EVP_sha512());
}

QString OpenHash::sha3_224()
{
	return Calculate(EVP_sha3_224());
}

QString OpenHash::sha3_256()
{
	return Calculate(EVP_sha3_256());
}

QString OpenHash::sha3_384()
{
	return Calculate(EVP_sha3_384());
}

QString OpenHash::sha3_512()
{
	return Calculate(EVP_sha3_512());
}

QString OpenHash::sha512_224()
{
	return Calculate(EVP_sha512_224());
}

QString OpenHash::sha512_256()
{
	return Calculate(EVP_sha512_256());
}

QString OpenHash::shake128()
{
	return Calculate(EVP_shake128());
}

QString OpenHash::shake256()
{
	return Calculate(EVP_shake256());
}

#ifndef OPENSSL_NO_BLAKE2
QString OpenHash::blake2b()
{
	return Calculate(EVP_blake2b512());
}

QString OpenHash::blake2s()
{
	return Calculate(EVP_blake2s256());
}

QString OpenHash::whirlpool()
{
	return Calculate(EVP_whirlpool());
}
#endif

QString OpenHash::hashToString(const Hash& hash)
{
	switch (hash)
	{
	case Hash::crc32:
		return "CRC32";
	case Hash::crc32c:
		return "CRC32C";
	case Hash::md4:
		return "MD4";
	case Hash::md5:
		return "MD5";
	case Hash::sha1:
		return "SHA1";
	case Hash::sha224:
		return "SHA224";
	case Hash::sha256:
		return "SHA256";
	case Hash::sha384:
		return "SHA384";
	case Hash::sha512:
		return "SHA512";
	case Hash::sha3_224:
		return "SHA3-224";
	case Hash::sha3_256:
		return "SHA3-256";
	case Hash::sha3_384:
		return "SHA3-384";
	case Hash::sha3_512:
		return "SHA3-512";
	case Hash::sha512_224:
		return "SHA512-224";
	case Hash::sha512_256:
		return "SHA512-256";
	case Hash::shake128:
		return "SHAKE128";
	case Hash::shake256:
		return "SHAKE256";
	case Hash::blake2b:
		return "BLAKE2B";
	case Hash::blake2s:
		return "BLAKE2S";
	case Hash::whirlpool:
		return "WHIRLPOOL";
	default:
		return "";
	}
}

QString OpenHash::Calculate(const EVP_MD* type)
{
	Sentry sentry = Sentry(this);
	if (m_file.isEmpty())
	{
		return QString();
	}

	QFile file(m_file);
	if (!file.open(QIODevice::ReadOnly))
	{
		return QString();
	}

	EVP_MD_CTX* md_ctx;

	if ((md_ctx = EVP_MD_CTX_new()) == nullptr)
	{
		return QString();
	}

	if (!EVP_DigestInit_ex(md_ctx, type, nullptr))
	{
		return QString();
	}

	char buffer[BUFFER_SIZE];
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	int progress = 0;
	qint64 fsize = file.size();
	qint64 total = 0;

	while (!file.atEnd())
	{
		qint64 bytes = file.read(buffer, sizeof(buffer));
		total += bytes;
		if (!EVP_DigestUpdate(md_ctx, buffer, bytes))
		{
			EVP_MD_CTX_free(md_ctx);
			return QString();
		}

		auto val = static_cast<int>((total * 1.0 / fsize) * 100 + 0.5);
		if (progress != val)
		{
			progress = val;
			emit percent(val);
		}
	}

	file.close();

	if (!EVP_DigestFinal_ex(md_ctx, digest, &digest_length))
	{
		EVP_MD_CTX_free(md_ctx);
		return QString();
	}

	EVP_MD_CTX_free(md_ctx);

	QString result;
	for (unsigned int i = 0; i < digest_length; ++i)
	{
		result += QString("%1").arg(digest[i], 2, 16, QChar('0')).toUpper();
	}
	return result;
}

QList<QPair<Hash, QString>> OpenHash::Calculate(const QList<Hash>& hashs)
{
	Sentry sentry = Sentry(this);
	if (m_file.isEmpty())
	{
		return {};
	}

	QFile file(m_file);
	if (!file.open(QIODevice::ReadOnly))
	{
		return {};
	}

	QList<QPair<Hash, QString>> result;
	bool has_crc32 = false;
	bool has_crc32c = false;
	CRC32_CTX crc32;
	CRC32C_CTX crc32c;

	QMap<Hash, QPair<EVP_MD_CTX*, const EVP_MD*>> ctxs;
	for (auto& hash : hashs)
	{
		if (hash == Hash::crc32)
		{
			has_crc32 = true;
			continue;
		}
		if (hash == Hash::crc32c)
		{
			has_crc32c = true;
			continue;
		}
#ifndef OPENSSL_NO_MD2
		if (hash == Hash::md2)
		{

			ctxs.append(qMakePair(EVP_MD_CTX_new(), EVP_md2()));

			continue;
		}
#endif
#ifndef OPENSSL_NO_MD4
		if (hash == Hash::md4)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_md4()));
			continue;
		}
#endif
#ifndef OPENSSL_NO_MD5
		if (hash == Hash::md5)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_md5()));
			continue;
		}
#endif
		if (hash == Hash::sha1)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha1()));
			continue;
		}
		if (hash == Hash::sha224)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha224()));
			continue;
		}
		if (hash == Hash::sha256)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha256()));
			continue;
		}
		if (hash == Hash::sha384)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha384()));
			continue;
		}
		if (hash == Hash::sha512)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha512()));
			continue;
		}
		if (hash == Hash::sha3_224)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha3_224()));
			continue;
		}
		if (hash == Hash::sha3_256)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha3_256()));
			continue;
		}
		if (hash == Hash::sha3_384)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha3_384()));
			continue;
		}
		if (hash == Hash::sha3_512)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha3_512()));
			continue;
		}if (hash == Hash::sha512_224)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha512_224()));
			continue;
		}
		if (hash == Hash::sha512_256)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_sha512_256()));
			continue;
		}
		if (hash == Hash::shake128)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_shake128()));
			continue;
		}
		if (hash == Hash::shake256)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_shake256()));
			continue;
		}
#ifndef OPENSSL_NO_BLAKE2
		if (hash == Hash::blake2b)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_blake2b512()));
			continue;
		}
		if (hash == Hash::blake2s)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_blake2s256()));
			continue;
		}
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
		if (hash == Hash::whirlpool)
		{
			ctxs.insert(hash, qMakePair(EVP_MD_CTX_new(), EVP_whirlpool()));
			continue;
		}
#endif
	}

	if (has_crc32)
	{
		CRC32_Init(&crc32);
	}

	if (has_crc32c)
	{
		CRC32C_Init(&crc32c);
	}

	QMapIterator<Hash, QPair<EVP_MD_CTX*, const EVP_MD*>> it(ctxs);
	QList<bool> success;
	auto size = ctxs.size();
	success.reserve(size);
	for (int i = 0; i < size; ++i)
	{
		success.append(true);
	}

	int index = 0;
	while (it.hasNext())
	{
		it.next();
		if (!EVP_DigestInit_ex(it.value().first, it.value().second, nullptr))
		{
			success[index] = false;
		}
		++index;
	}

	char buffer[BUFFER_SIZE];
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	int progress = 0;
	qint64 fsize = file.size();
	qint64 total = 0;

	while (!file.atEnd())
	{
		it.toFront();
		index = 0;
		qint64 bytes = file.read(buffer, sizeof(buffer));
		total += bytes;
		if (has_crc32)
		{
			CRC32_Update(&crc32, buffer, bytes);
		}

		if (has_crc32c)
		{
			CRC32C_Update(&crc32c, buffer, bytes);
		}

		while (it.hasNext())
		{
			it.next();
			if (!success[index] || !EVP_DigestUpdate(it.value().first, buffer, bytes))
			{
				success[index] = false;
			}
			++index;
		}

		auto val = static_cast<int>((total * 1.0 / fsize) * 100 + 0.5);
		if (progress != val)
		{
			progress = val;
			emit percent(val);
		}
	}

	file.close();

	unsigned char digest_crc32[CRC32_DIGEST_LENGTH];
	unsigned char digest_crc32c[CRC32C_DIGEST_LENGTH];

	if (has_crc32)
	{
		QString hexstring;
		CRC32_Final(digest_crc32, &crc32);
		for (int i = 0; i < CRC32_DIGEST_LENGTH; ++i)
		{
			hexstring += QString("%1").arg(digest_crc32[i], 2, 16, QChar('0')).toUpper();
		}
		result << qMakePair(Hash::crc32, hexstring);
	}

	if (has_crc32c)
	{
		QString hexstring;
		CRC32C_Final(digest_crc32c, &crc32c);
		for (int i = 0; i < CRC32C_DIGEST_LENGTH; ++i)
		{
			hexstring += QString("%1").arg(digest_crc32c[i], 2, 16, QChar('0')).toUpper();
		}
		result << qMakePair(Hash::crc32c, hexstring);
	}

	it.toFront();
	index = 0;
	while (it.hasNext())
	{
		it.next();
		if (!success[index] || !EVP_DigestFinal_ex(it.value().first, digest, &digest_length))
		{
			success[index] = false;
		}

		EVP_MD_CTX_free(it.value().first);

		QString hexstring;
		if (success[index])
		{
			for (unsigned int i = 0; i < digest_length; ++i)
			{
				hexstring += QString("%1").arg(digest[i], 2, 16, QChar('0')).toUpper();
			}
		}

		result << qMakePair(it.key(), hexstring);
		++index;
	}

	return result;
}
