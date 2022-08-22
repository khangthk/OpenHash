#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setOrganizationName("FreeTool");
    a.setApplicationName("OpenHash");

    MainWindow w;
    w.show();
    return a.exec();
}
