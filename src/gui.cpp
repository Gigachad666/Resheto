#include "gui/mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QStandardPaths>
int main(int argc,char **argv) {
    QApplication app(argc,argv); app.setApplicationName("Resheto");
    QCommandLineParser p; p.setApplicationDescription(QStringLiteral("АС Решето")); p.addHelpOption();
    p.addOption({"path",QStringLiteral("Начальная область проверки"),"path"});
    p.addOption({"db",QStringLiteral("База сигнатур"),"path"}); p.addOption({"storage",QStringLiteral("Хранилище результатов"),"path"}); p.process(app);
    resheto::Request request; request.path=p.value("path"); request.signaturePath=p.value("db"); request.storagePath=p.value("storage");
    if(request.storagePath.isEmpty()) {
        const auto dir=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation); QDir().mkpath(dir); request.storagePath=dir+"/resheto.db";
    }
    resheto::MainWindow window(request); window.show(); return app.exec();
}
