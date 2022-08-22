#include "calctask.h"

#include <QDebug>

CalcTask::CalcTask(const QString& file, const QList<Hash>& hashs)
{
	m_hashs = hashs;
	m_openhash = new OpenHash(file);
	connect(m_openhash, &OpenHash::percent, this, &CalcTask::percent);
}

CalcTask::~CalcTask()
{
	qDebug() << "~CalcTask";
	delete m_openhash;
}

void CalcTask::GetResult(QList<QPair<Hash, QString>>& output)
{
	output = m_output;
}

void CalcTask::run()
{

	if (m_hashs.empty())
	{
		return;
	}
	else if (m_hashs.count() == 1)
	{
		QString value;
		auto hash = m_hashs.first();
		switch (hash) {
		case Hash::crc32:
			value = m_openhash->crc32();
			m_output << qMakePair(Hash::crc32, value);
			break;
		case Hash::crc32c:
			value = m_openhash->crc32();
			m_output << qMakePair(Hash::crc32c, value);
			break;
		case Hash::md4:
			value = m_openhash->md4();
			m_output << qMakePair(Hash::md4, value);
			break;
		case Hash::md5:
			value = m_openhash->md5();
			m_output << qMakePair(Hash::md5, value);
			break;
		case Hash::sha1:
			value = m_openhash->sha1();
			m_output << qMakePair(Hash::sha1, value);
			break;
		case Hash::sha224:
			value = m_openhash->sha224();
			m_output << qMakePair(Hash::sha224, value);
			break;
		case Hash::sha256:
			value = m_openhash->sha256();
			m_output << qMakePair(Hash::sha256, value);
			break;
		case Hash::sha384:
			value = m_openhash->sha384();
			m_output << qMakePair(Hash::sha384, value);
			break;
		case Hash::sha512:
			value = m_openhash->sha512();
			m_output << qMakePair(Hash::sha512, value);
			break;
		case Hash::sha3_224:
			value = m_openhash->sha3_224();
			m_output << qMakePair(Hash::sha3_224, value);
			break;
		case Hash::sha3_256:
			value = m_openhash->sha3_256();
			m_output << qMakePair(Hash::sha3_256, value);
			break;
		case Hash::sha3_384:
			value = m_openhash->sha3_384();
			m_output << qMakePair(Hash::sha3_384, value);
			break;
		case Hash::sha3_512:
			value = m_openhash->sha3_512();
			m_output << qMakePair(Hash::sha3_512, value);
			break;
		case Hash::sha512_224:
			value = m_openhash->sha512_224();
			m_output << qMakePair(Hash::sha512_224, value);
			break;
		case Hash::sha512_256:
			value = m_openhash->sha512_256();
			m_output << qMakePair(Hash::sha512_256, value);
			break;
		case Hash::shake128:
			value = m_openhash->shake128();
			m_output << qMakePair(Hash::shake128, value);
			break;
		case Hash::shake256:
			value = m_openhash->shake256();
			m_output << qMakePair(Hash::shake256, value);
			break;
		case Hash::blake2b:
			value = m_openhash->blake2b();
			m_output << qMakePair(Hash::blake2b, value);
			break;
		case Hash::blake2s:
			value = m_openhash->blake2s();
			m_output << qMakePair(Hash::blake2s, value);
			break;
		case Hash::whirlpool:
			value = m_openhash->whirlpool();
			m_output << qMakePair(Hash::whirlpool, value);
			break;
		default:
			break;
		}
	}
	else
	{
		m_output = m_openhash->Calculate(m_hashs);
	}
}
