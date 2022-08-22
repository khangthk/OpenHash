#pragma once

#include "openhash.h"
#include <QThread>

class CalcTask : public QThread
{
	Q_OBJECT
public:
	CalcTask(const QString& file, const QList<Hash>& hashs);
	~CalcTask();

	void GetResult(QList<QPair<Hash, QString>>& output);

protected:
	void run() override;

private:
	QList<Hash> m_hashs;
	OpenHash* m_openhash;
	QList<QPair<Hash, QString>> m_output;

signals:
	void percent(const int percent);
};
