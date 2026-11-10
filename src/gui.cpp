#include "gui/mainwindow.h"
#include "gui/startup.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QStandardPaths>
int main(int argc,char **argv) {
    QApplication app(argc,argv);
    app.setApplicationName("Resheto");
    QCommandLineParser parser;
    resheto::addGuiOptions(parser,QDir(QCoreApplication::applicationDirPath()),QDir::current());
    parser.process(app);
    const auto startup=resheto::guiStartup(parser,QDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)));
    resheto::MainWindow window(startup.request,startup.behaviorPath,startup.processScope,startup.watchPath,startup.networkRules);
    window.show();
    return app.exec();
}
