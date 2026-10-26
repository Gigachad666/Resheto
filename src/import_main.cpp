#include "core/import.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QJsonDocument>
#include <QTextStream>
using namespace resheto;
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); QCommandLineParser p; p.addHelpOption();
    p.setApplicationDescription(QStringLiteral("Офлайн-импорт и выбор рабочей базы АС Решето"));
    for(const auto &name:{"input","format","repository","version","provenance","activate"}) p.addOption({name,QString::fromLatin1(name),"value"});
    try {
        if(!p.parse(app.arguments())) throw Error(p.errorText()); if(p.isSet("help")) p.showHelp();
        if(!p.isSet("repository")) throw Error(QStringLiteral("Требуется --repository"));
        if(p.isSet("activate")) { activateVersion(p.value("repository"),p.value("activate")); return 0; }
        QFile f(p.value("provenance")); if(!f.open(QIODevice::ReadOnly) || f.size()>1024*1024) throw Error(QStringLiteral("Не открыть provenance JSON"));
        QJsonParseError e; const auto doc=QJsonDocument::fromJson(f.readAll(),&e); if(e.error!=QJsonParseError::NoError || !doc.isObject()) throw Error(QStringLiteral("Некорректный provenance JSON"));
        const auto report=importSnapshot({p.value("input"),p.value("format"),p.value("repository"),p.value("version"),doc.object()});
        QTextStream(stdout)<<QJsonDocument(report).toJson()<<Qt::endl; return 0;
    } catch(const Error &e) { QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
