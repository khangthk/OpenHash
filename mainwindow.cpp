#include "mainwindow.h"
#include "openhash.h"
#include "setting.h"
#include "calctask.h"

#include "ui_mainwindow.h"

#include <QMimeData>
#include <QFileDialog>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), m_lastPath("")
{
    ui->setupUi(this);
    setAcceptDrops(true);
    m_progressbar.setRange(0, 100);
    m_progressbar.setFixedHeight(20);
    m_progressbar.setFixedWidth(200);
    m_progressbar.setTextVisible(false);
    m_progressbar.hide();
    ui->statusBar->addPermanentWidget(&m_progressbar);
    initState();

    connect(ui->calculate, &QPushButton::clicked, this, &MainWindow::onCalculate);
    connect(ui->browse, &QPushButton::clicked, this, &MainWindow::onBrowse);

    connect(ui->path, &QComboBox::currentTextChanged, [&](const QString& text)
    {
        m_lastPath = text;
    });

    connect(ui->crc32, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::crc32, state);
    });
    connect(ui->crc32c, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::crc32c, state);
    });
    connect(ui->md4, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::md4, state);
    });
    connect(ui->md5, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::md5, state);
    });
    connect(ui->sha1, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha1, state);
    });
    connect(ui->sha224, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha224, state);
    });
    connect(ui->sha256, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha256, state);
    });
    connect(ui->sha384, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha384, state);
    });
    connect(ui->sha512, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha512, state);
    });
    connect(ui->sha3_224, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha3_224, state);
    });
    connect(ui->sha3_256, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha3_256, state);
    });
    connect(ui->sha3_384, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha3_384, state);
    });
    connect(ui->sha3_512, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha3_512, state);
    });
    connect(ui->sha512_224, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha512_224, state);
    });
    connect(ui->sha512_256, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::sha512_256, state);
    });
    connect(ui->shake128, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::shake128, state);
    });
    connect(ui->shake256, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::shake256, state);
    });
    connect(ui->blake2b, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::blake2b, state);
    });
    connect(ui->blake2s, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::blake2s, state);
    });
    connect(ui->whirlpool, &QCheckBox::stateChanged, [](int state)
    {
        Setting::saveHash(Hash::whirlpool, state);
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event)
{
	qDebug() << "->dragEnterEvent";
	const QMimeData* mimeData = event->mimeData();
	auto files = mimeData->urls();
	if (files.size() != 1)
	{
		return;
	}

	auto file = files.at(0).toLocalFile();
	if (!QFileInfo(file).isFile())
	{
		return;
	}

	event->acceptProposedAction();
}

void MainWindow::dropEvent(QDropEvent* event)
{
	qDebug() << "->dropEvent";
	const QMimeData* mimeData = event->mimeData();
	if (!mimeData->hasUrls() || mimeData->urls().size() != 1)
	{
		return;
	}

	event->acceptProposedAction();

    m_lastPath = QDir::toNativeSeparators(mimeData->urls().at(0).toLocalFile());

	if (ui->path->findText(m_lastPath) == -1)
	{
		if (ui->path->count() >= 10)
		{
			ui->path->removeItem(ui->path->count() - 1);
		}
		ui->path->insertItem(0, m_lastPath);
		ui->path->setCurrentIndex(0);
	}
}

void MainWindow::initState()
{
    ui->crc32->setChecked(Setting::getHash(Hash::crc32));
    ui->crc32c->setChecked(Setting::getHash(Hash::crc32c));
    ui->md4->setChecked(Setting::getHash(Hash::md4));
    ui->md5->setChecked(Setting::getHash(Hash::md5));
    ui->sha1->setChecked(Setting::getHash(Hash::sha1));
    ui->sha224->setChecked(Setting::getHash(Hash::sha224));
    ui->sha256->setChecked(Setting::getHash(Hash::sha256));
    ui->sha384->setChecked(Setting::getHash(Hash::sha384));
    ui->sha512->setChecked(Setting::getHash(Hash::sha512));
    ui->sha3_224->setChecked(Setting::getHash(Hash::sha3_224));
    ui->sha3_256->setChecked(Setting::getHash(Hash::sha3_256));
    ui->sha3_384->setChecked(Setting::getHash(Hash::sha3_384));
    ui->sha3_512->setChecked(Setting::getHash(Hash::sha3_512));
    ui->sha512_224->setChecked(Setting::getHash(Hash::sha512_224));
    ui->sha512_256->setChecked(Setting::getHash(Hash::sha512_256));
    ui->shake128->setChecked(Setting::getHash(Hash::shake128));
    ui->shake256->setChecked(Setting::getHash(Hash::shake256));
    ui->blake2b->setChecked(Setting::getHash(Hash::blake2b));
    ui->blake2s->setChecked(Setting::getHash(Hash::blake2s));
    ui->whirlpool->setChecked(Setting::getHash(Hash::whirlpool));
}

void MainWindow::onCalculate()
{
    if (m_lastPath.isEmpty())
    {
        return;
    }

    QList<Hash> hashs;
    if (ui->crc32->isChecked()) {hashs << Hash::crc32;}
    if (ui->crc32c->isChecked()) {hashs << Hash::crc32c;}
    if (ui->md4->isChecked()) {hashs << Hash::md4;}
    if (ui->md5->isChecked()) {hashs << Hash::md5;}
    if (ui->sha1->isChecked()) {hashs << Hash::sha1;}
    if (ui->sha224->isChecked()) {hashs << Hash::sha224;}
    if (ui->sha256->isChecked()) {hashs << Hash::sha256;}
    if (ui->sha384->isChecked()) {hashs << Hash::sha384;}
    if (ui->sha512->isChecked()) {hashs << Hash::sha512;}
    if (ui->sha3_224->isChecked()) {hashs << Hash::sha3_224;}
    if (ui->sha3_256->isChecked()) {hashs << Hash::sha3_256;}
    if (ui->sha3_384->isChecked()) {hashs << Hash::sha3_384;}
    if (ui->sha3_512->isChecked()) {hashs << Hash::sha3_512;}
    if (ui->sha512_224->isChecked()) {hashs << Hash::sha512_224;}
    if (ui->sha512_256->isChecked()) {hashs << Hash::sha512_256;}
    if (ui->shake128->isChecked()) {hashs << Hash::shake128;}
    if (ui->shake256->isChecked()) {hashs << Hash::shake256;}
    if (ui->blake2b->isChecked()) {hashs << Hash::blake2b;}
    if (ui->blake2s->isChecked()) {hashs << Hash::blake2s;}
    if (ui->whirlpool->isChecked()) {hashs << Hash::whirlpool;}

    if (!hashs.empty())
    {
        m_calcTask.reset(new CalcTask(m_lastPath, hashs));
        connect(m_calcTask.get(), &CalcTask::started, this, [&]()
                {
                  ui->calculate->setEnabled(false);
                  ui->calculate->setText("Calculating...");
                  ui->outputEdit->clear();
                  m_progressbar.show();
                  m_progressbar.setValue(0);
                });

        connect(m_calcTask.get(), &CalcTask::finished, this, [&]()
                {
                  ui->calculate->setEnabled(true);
                  ui->calculate->setText("Calculate");
                  m_progressbar.hide();

                  QList<QPair<Hash, QString>> result;
                  m_calcTask->GetResult(result);

                  if (!result.empty())
                  {
                    QFileInfo info(m_lastPath);
                    QString fileName = info.fileName();

                    QString html = "<table>";
                    html += QString("<tr><td align=right>%1: </td><td>%2</td></tr>").arg("FILE", fileName);
                    for (auto& val : result)
                    {
                        html += QString("<tr><td align=right>%1: </td><td>%2</td></tr>").arg(OpenHash::hashToString(val.first), val.second);
                    }
                    html += "</table>";
                    ui->outputEdit->setHtml(html);
                  }
                });

        connect(m_calcTask.get(), &CalcTask::percent, this, [&](const int percent)
          {
            qDebug() << percent;
            m_progressbar.setValue(percent);
          });

        m_calcTask->start();
    }
}

void MainWindow::onBrowse()
{
    QString path = QFileDialog::getOpenFileName(this, "Select File", m_lastPath);

    if (!path.isEmpty())
    {
        m_lastPath = QDir::toNativeSeparators(path);
        if (ui->path->findText(m_lastPath) == -1)
        {
            if (ui->path->count() >= 10)
            {
                ui->path->removeItem(ui->path->count() - 1);
            }
            ui->path->insertItem(0, m_lastPath);
            ui->path->setCurrentIndex(0);
        }
    }
}
