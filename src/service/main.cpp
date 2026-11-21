#include "server.h"
#include "settings.h"
#ifdef _WIN32
#include "windows_service.h"
#include "diagnostics.h"
#include <string_view>
#endif
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTextStream>
#include <QTimer>
#include <csignal>

namespace {
volatile std::sig_atomic_t stopRequested=0;
void requestStop(int) { stopRequested=1; }
void startupError(const QString &message) {
#ifdef Q_OS_WIN
    if(resheto::service::runningUnderScm()) {
        resheto::service::logSystemError(message);
        return;
    }
#endif
    QTextStream(stderr)<<message<<Qt::endl;
}
}

namespace {
int runApplication(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    QCoreApplication::setApplicationName("resheto-service");
    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("АС Решето. Служба проверки и наблюдения текущего пользователя"));
    const auto help=parser.addHelpOption();
    parser.addOption({"config",QStringLiteral("JSON настроек службы"),"file"});
    parser.addOption({"endpoint",QStringLiteral("Уникальное имя локального соединения"),"name"});
    parser.addOption({"db",QStringLiteral("Рабочая версия базы сигнатур"),"file"});
    parser.addOption({"heuristics",QStringLiteral("Правила статической эвристики"),"file"});
    parser.addOption({"storage",QStringLiteral("История SQLite"),"file"});
#ifdef Q_OS_WIN
    parser.addOption({"scm",QStringLiteral("Запуск под управлением Windows SCM")});
#endif
#ifdef RESHETO_SERVICE_NETWORK
    parser.addOption({"network-rules",QStringLiteral("Правила сетевого анализа"),"file"});
#endif
    try {
        if(!parser.parse(app.arguments()))throw resheto::Error(parser.errorText());
        if(parser.isSet(help)){QTextStream(stdout)<<parser.helpText();return 0;}
        if(!parser.positionalArguments().isEmpty())throw resheto::Error(QStringLiteral("Неожиданный позиционный аргумент"));
        auto settings=parser.isSet("config") ? resheto::service::loadSettings(parser.value("config")) : resheto::service::Settings{};
        if(parser.isSet("endpoint"))settings.endpoint=parser.value("endpoint");
        if(parser.isSet("db"))settings.scan.signaturePath=parser.value("db");
        if(parser.isSet("heuristics"))settings.scan.heuristicPath=parser.value("heuristics");
        if(parser.isSet("storage"))settings.scan.storagePath=parser.value("storage");
#ifdef RESHETO_SERVICE_NETWORK
        if(parser.isSet("network-rules"))settings.networkRulesPath=parser.value("network-rules");
#endif
        std::signal(SIGINT,requestStop);
        std::signal(SIGTERM,requestStop);
        QTimer stopTimer;
        QObject::connect(&stopTimer,&QTimer::timeout,&app,[&app]{
#ifdef Q_OS_WIN
            if(resheto::service::scmStopRequested()){app.quit();return;}
#endif
            if(stopRequested)app.quit();
        });
        stopTimer.start(100);
        return resheto::service::serve(settings.endpoint,std::move(settings.scan),settings.networkRulesPath);
    } catch(const resheto::Error &error) {
        startupError(error.message);
        return 2;
    } catch(const std::exception &error) {
        startupError(QString::fromUtf8(error.what()));
        return 2;
    }
}
}

int main(int argc,char **argv) {
#ifdef _WIN32
    for(int i=1;i<argc;++i)
        if(std::string_view(argv[i])=="--scm")return resheto::service::runUnderScm(argc,argv,runApplication);
#endif
    return runApplication(argc,argv);
}
