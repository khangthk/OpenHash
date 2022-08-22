QT       += core gui widgets

CONFIG += c++17

DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000

RC_ICONS = sha-256.ico

include(3rdparty/openssl.pri)

SOURCES += \
    calctask.cpp \
    crc32.cpp \
    crc32c.cpp \
    main.cpp \
    mainwindow.cpp \
    openhash.cpp \
    setting.cpp

HEADERS += \
    calctask.h \
    crc32.h \
    crc32c.h \
    mainwindow.h \
    openhash.h \
    setting.h

FORMS += \
    mainwindow.ui

RESOURCES += \
    OpenHash.qrc

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
