#include "gui/mainwindow.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QStandardPaths>
int main(int argc,char **argv) {
    QApplication app(argc,argv); app.setApplicationName("Resheto");
    QCommandLineParser p; p.setApplicationDescription(QStringLiteral("АС Решето")); p.addHelpOption();
    p.addOption({"path",QStringLiteral("Начальная область проверки"),"path"});
    p.addOption({"heuristics",QStringLiteral("Эвристические правила"),"path"}); p.addOption({"behavior",QStringLiteral("Поведенческие правила"),"path"});
    p.addOption({"process-scope",QStringLiteral("Каталог программ для наблюдения"),"path"});
    p.addOption({"watch-path",QStringLiteral("Каталог файлового наблюдения (независимо от ручной проверки)"),"path"});
    p.addOption({"db",QStringLiteral("База сигнатур"),"path"}); p.addOption({"storage",QStringLiteral("Хранилище результатов"),"path"}); p.process(app);
    resheto::Request request; request.path=p.value("path"); request.signaturePath=p.value("db"); request.storagePath=p.value("storage");
    request.heuristicPath=p.value("heuristics");
    if(request.storagePath.isEmpty()) {
        const auto dir=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation); QDir().mkpath(dir); request.storagePath=dir+"/resheto.db";
    }
    resheto::MainWindow window(request,p.value("behavior"),p.value("process-scope"),p.value("watch-path")); window.show(); return app.exec();
}
