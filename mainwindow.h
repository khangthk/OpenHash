#pragma once

#include "calctask.h"

#include <QMainWindow>
#include <QString>
#include <QProgressBar>
#include <QDragEnterEvent>
#include <QDropEvent>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget* parent = nullptr);
	~MainWindow();

protected:
	void dragEnterEvent(QDragEnterEvent* event) override;
	void dropEvent(QDropEvent* event) override;

private:
	Ui::MainWindow* ui;
	QString m_lastPath;
	QProgressBar m_progressbar;
	std::unique_ptr<CalcTask> m_calcTask;

	void initState();

private slots:
	void onCalculate();
	void onBrowse();
};
