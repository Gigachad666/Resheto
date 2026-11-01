#include "core/api.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QTextStream>
#include <csignal>
#include <thread>
#include <chrono>
using namespace resheto;
namespace {
volatile std::sig_atomic_t interrupted=0;
void signalHandler(int) { interrupted=1; }
void line(const QJsonObject &o) { QTextStream(stdout)<<QJsonDocument(o).toJson(QJsonDocument::Compact)<<Qt::endl; }
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); QCommandLineParser p; p.addHelpOption(); p.setApplicationDescription(QStringLiteral("АС Решето — наблюдение за выбранными файлами и жизненным циклом процессов"));
    p.addOption({"path",QStringLiteral("Наблюдаемый каталог"),"directory"}); p.addOption({"db",QStringLiteral("Сигнатурная база"),"file"});
    p.addOption({"heuristics",QStringLiteral("Статические JSON-правила"),"file"}); p.addOption({"behavior",QStringLiteral("Поведенческие JSON-правила"),"file"});
    p.addOption({"storage",QStringLiteral("История SQLite"),"file"}); p.addOption({"process-scope",QStringLiteral("Каталог образов родителей для правил поведения; по умолчанию --path"),"directory"});
    p.addOption({"duration-ms",QStringLiteral("Длительность 1..600000 мс; затем отмена с кодом 3"),"ms","5000"});
    p.addOption({"no-processes",QStringLiteral("Только файловые события")}); p.addOption({"non-recursive",QStringLiteral("Без подкаталогов")});
    p.addOption({"no-files",QStringLiteral("Не наблюдать файловые события")}); p.addOption({"scan-process-images",QStringLiteral("Проверять файлы наблюдаемых процессов общим файловым маршрутом")});
    p.addOption({"list-processes",QStringLiteral("Получить один снимок процессов и завершить")}); p.addOption({"json",QStringLiteral("JSON Lines")});
    bool json=app.arguments().contains("--json");
    try {
        if(!p.parse(app.arguments())) throw Error(p.errorText()); json=p.isSet("json");
        if(p.isSet("help")) { QTextStream(stdout)<<p.helpText(); return 0; }
        if(p.isSet("list-processes")) {
            const auto snapshot=processSnapshot();
            for(const auto &info:snapshot.processes) { if(json) line({{"type","process"},{"data",info.json()}}); else QTextStream(stdout)<<info.pid<<" "<<info.parentPid<<" "<<info.startTime<<" "<<info.image<<Qt::endl; }
            if(json) line({{"type","coverage"},{"available",snapshot.available},{"complete",snapshot.complete},{"reason",snapshot.reason},{"source","process_snapshot"}});
            else QTextStream(stdout)<<QStringLiteral("Ограниченный снимок; ")<<snapshot.reason<<Qt::endl;
            return snapshot.available?0:2;
        }
        bool ok=false; const auto duration=p.value("duration-ms").toLongLong(&ok);
        if(!ok || duration<1 || duration>600000) throw Error(QStringLiteral("duration-ms должен быть 1..600000"));
        if(!p.isSet("storage")) throw Error(QStringLiteral("Требуется --storage"));
        MonitorRequest r; r.directory=p.value("path"); r.signaturePath=p.value("db"); r.heuristicPath=p.value("heuristics"); r.behaviorPath=p.value("behavior"); r.storagePath=p.value("storage");
        r.processImageDirectory=p.value("process-scope"); r.processes=!p.isSet("no-processes"); r.recursive=!p.isSet("non-recursive"); r.files=!p.isSet("no-files"); r.scanProcessImages=p.isSet("scan-process-images");
        if(r.processes && r.behaviorPath.isEmpty() && !r.scanProcessImages) throw Error(QStringLiteral("Укажите --behavior или --scan-process-images либо --no-processes"));
        std::signal(SIGINT,signalHandler); std::signal(SIGTERM,signalHandler);
        MonitorRuntime runtime; runtime.start(r); QElapsedTimer elapsed; elapsed.start(); QString previous;
        while(runtime.status().active && !interrupted && elapsed.elapsed()<duration) {
            const auto s=runtime.status(); const auto key=s.state+QString::number(s.job.results)+QString::number(s.lost)+(s.ready?"ready":"starting");
            if(key!=previous) {
                previous=key;
                if(json) line({{"type","monitor_status"},{"state",s.state},{"ready",s.ready},{"coverage",s.coverage},{"reason",s.reason},{"lost",QString::number(s.lost)},{"data",s.job.json()}});
                else QTextStream(stdout)<<monitorStateText(s.state)<<": "<<s.coverage<<" "<<s.reason<<QStringLiteral("; обнаружений %1").arg(s.job.matches)<<Qt::endl;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        runtime.cancel(); runtime.wait(); const auto final=runtime.status();
        if(!final.job.id.isEmpty()) {
            Store history(r.storagePath,true); qint64 cursor=0;
            while(true) { const auto rows=history.page(final.job.id,cursor); if(rows.empty()) break; cursor=history.lastRow();
                for(const auto &result:rows) { if(json) line({{"type","result"},{"data",result.json()}}); else QTextStream(stdout)<<result.path<<": "<<outcomeText(result)<<" "<<result.basis<<Qt::endl; } }
        }
        if(json) line({{"type","job"},{"data",final.job.json()},{"exit_code",final.job.exitCode()},{"coverage",final.coverage},{"reason",final.reason}});
        else QTextStream(stdout)<<stateText(final.job.state)<<"; "<<final.reason<<Qt::endl;
        return final.job.exitCode();
    } catch(const Error &e) { if(json) line({{"type","error"},{"error",e.message},{"exit_code",2}}); else QTextStream(stderr)<<e.message<<Qt::endl; return 2; }
}
