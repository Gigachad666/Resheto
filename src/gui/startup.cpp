#include "startup.h"
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>

namespace resheto {
namespace {
const auto signaturesFile=QStringLiteral("distribution/working/current.json");
const auto heuristicsFile=QStringLiteral("data/heuristic_rules.json");

QDir assetsDirectory(const QDir &executableDir,const QDir &workingDir) {
    for(auto dir:{executableDir,workingDir}) {
        do {
            if(QFileInfo(dir.filePath(signaturesFile)).isFile() || QFileInfo(dir.filePath(heuristicsFile)).isFile())
                return dir;
        } while(!dir.isRoot() && dir.cdUp());
    }
    return executableDir;
}

QString defaultArea(const QCommandLineParser &parser,const QString &option,const QDir &areas,const QString &name) {
    if(parser.isSet(option))return parser.value(option);
    const auto path=areas.absoluteFilePath(name);
    QDir().mkpath(path);
    return path;
}
}

void addGuiOptions(QCommandLineParser &parser,const QDir &executableDir,const QDir &workingDir) {
    const auto assets=assetsDirectory(executableDir,workingDir);
    parser.setApplicationDescription(QStringLiteral("АС Решето"));
    parser.addHelpOption();
    parser.addOption({"path",QStringLiteral("Начальная область проверки"),"path"});
    parser.addOption({"heuristics",QStringLiteral("Эвристические правила"),"path",assets.absoluteFilePath(heuristicsFile)});
    parser.addOption({"behavior",QStringLiteral("Поведенческие правила"),"path",assets.absoluteFilePath("data/behavior_rules.json")});
    parser.addOption({"process-scope",QStringLiteral("Каталог программ для наблюдения"),"path"});
    parser.addOption({"watch-path",QStringLiteral("Каталог файлового наблюдения"),"path"});
    parser.addOption({"db",QStringLiteral("База сигнатур"),"path",assets.absoluteFilePath(signaturesFile)});
    parser.addOption({"storage",QStringLiteral("Хранилище результатов"),"path"});
#ifdef RESHETO_WITH_NETWORK
    parser.addOption({"network-rules",QStringLiteral("Сетевые правила"),"path",assets.absoluteFilePath("data/network_rules.json")});
#endif
}

GuiStartup guiStartup(const QCommandLineParser &parser,const QDir &localDataDir) {
    GuiStartup settings;
    auto &request=settings.request;
    request.signaturePath=parser.value("db");
    request.heuristicPath=parser.value("heuristics");
    request.storagePath=parser.value("storage");
    if(request.storagePath.isEmpty())request.storagePath=localDataDir.absoluteFilePath("resheto.db");

    const QDir historyDirectory(QFileInfo(request.storagePath).absolutePath());
    const QDir areas(historyDirectory.filePath("resheto-work"));
    settings.watchPath=defaultArea(parser,"watch-path",areas,"watched");
    settings.processScope=defaultArea(parser,"process-scope",areas,"processes");
    request.path=parser.isSet("path")?parser.value("path"):settings.watchPath;
    settings.behaviorPath=parser.value("behavior");
#ifdef RESHETO_WITH_NETWORK
    settings.networkRules=parser.value("network-rules");
#endif
    return settings;
}
}
