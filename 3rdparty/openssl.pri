win32 {
    !contains(QMAKE_TARGET.arch, x86_64) {
        ARCH = x86
    } else {
        ARCH = x64
    }
}

CONFIG(debug, debug|release): {
    LIB_PATH = $$PWD/bin/$${ARCH}/debug/openssl/lib
} else {
    LIB_PATH = $$PWD/bin/$${ARCH}/release/openssl/lib
}

HEADER_PATH = $$PWD/bin/$${ARCH}/release/openssl/include

INCLUDEPATH += $${HEADER_PATH}
DEPENDPATH += $${HEADER_PATH}

win32 {LIBS += -lcrypt32 -ladvapi32 -lcomdlg32 -lgdi32 -liphlpapi -lkernel32 -lnetapi32 -lole32 -loleaut32 -lshell32 -luser32 -luuid -lwinspool -lws2_32 -lwsock32}

LIBS += -L$${LIB_PATH} -llibcrypto 

PRE_TARGETDEPS += $${LIB_PATH}/libcrypto.lib
