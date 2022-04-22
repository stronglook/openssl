QT -= gui

CONFIG += c++11 console
CONFIG -= app_bundle

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
        main.cpp \
        pkey.cpp \
        rsa_key.cpp

QMAKE_CFLAGS += -fpermissive
QMAKE_CXXFLAGS += -fpermissive
QMAKE_LFLAGS += -fpermissive

INCLUDEPATH += "C:\Program Files\OpenSSL-Win64\include"
LIBS += "C:\Program Files\OpenSSL-Win64\bin\libcrypto-3-x64.dll"
LIBS += "C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll"

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

HEADERS += \
    pkey.h \
    rsa_key.h
