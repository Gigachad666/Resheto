#include "core/controller.h"
#include "core/database.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QElapsedTimer>
#include <QJsonDocument>
#include <QStandardPaths>
#include <QTextStream>
#include <csignal>
#include <chrono>
#include <thread>

using namespace resheto;
static volatile std::sig_atomic_t interrupted=0;
static void signalHandler(int) { interrupted=1; }
static void jsonLine(const QJsonObject &o) { QTextStream(stdout)<<QJsonDocument(o).toJson(QJsonDocument::Compact)<<'\n'; }
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv); app.setApplicationName("Resheto");
    QCommandLineParser p; p.setApplicationDescription(QStringLiteral("АС Решето — сигнатурное сканирование; JSON Lines: result*, job")); p.addHelpOption();
    p.addOption({"path",QStringLiteral("Файл или каталог"),"path"});
    p.addOption({"db",QStringLiteral("База сигнатур"),"file"});
    p.addOption({"storage",QStringLiteral("Хранилище результатов"),"file"});
    p.addOption({"non-recursive",QStringLiteral("Не входить в подкаталоги")});
    p.addOption({"json",QStringLiteral("Машинный вывод JSON Lines")});
    p.addOption({"last",QStringLiteral("Прочитать последнее сохранённое задание")});
    p.addOption({"cancel-after-ms",QStringLiteral("Отмена по таймеру (0 — до начала)"),"ms"});
    p.addOption({"block-size",QStringLiteral("Размер блока 4096..4194304"),"bytes","65536"});
    bool jsonRequested=false;
    // parse() не завершает процесс; --json учитывается и после неизвестной опции.
    const auto arguments=app.arguments();
    for(int i=1;i<arguments.size() && arguments[i]!="--";++i) if(arguments[i]=="--json") jsonRequested=true;
    try {
        if(!p.parse(arguments)) throw Error(QStringLiteral("Ошибка аргументов командной строки: ")+p.errorText());
        jsonRequested=p.isSet("json");
        if(p.isSet("help")) { QTextStream(stdout)<<p.helpText(); return 0; }
        QString storage=p.value("storage");
        if(storage.isEmpty()) {
            auto dir=QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
            if(!QDir().mkpath(dir)) throw Error(QStringLiteral("Не создать каталог данных"));
            storage=dir+"/resheto.db";
        }
        Job job;
        if(p.isSet("last")) {
            Store store(storage,true); auto j=store.latest();
            if(!j) throw Error(QStringLiteral("Нет сохранённых заданий")); job=*j;
        } else {
            if(!p.isSet("path") || !p.isSet("db")) throw Error(QStringLiteral("Требуются --path и --db"));
            Request request; request.path=p.value("path"); request.signaturePath=p.value("db"); request.storagePath=storage; request.recursive=!p.isSet("non-recursive");
            bool ok=false; request.blockSize=p.value("block-size").toLongLong(&ok);
            if(!ok) throw Error(QStringLiteral("Некорректный размер блока"));
            qint64 timeout=-1;
            if(p.isSet("cancel-after-ms")) { timeout=p.value("cancel-after-ms").toLongLong(&ok); if(!ok || timeout<0) throw Error(QStringLiteral("Некорректное время отмены")); }
            std::signal(SIGINT,signalHandler); std::signal(SIGTERM,signalHandler);
            if(timeout==0) *request.cancel=true;
            Controller controller; controller.submit(request); QElapsedTimer timer; timer.start();
            while(controller.busy()) {
                if(interrupted || (timeout>=0 && timer.elapsed()>=timeout)) controller.cancel();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            job=controller.progress();
        }
        // Читаем подтверждённые транзакциями строки; память ограничена одной страницей.
        if(!job.id.isEmpty()) {
            try {
                Store store(storage,true); qint64 cursor=0;
                while(true) {
                    auto rows=store.page(job.id,cursor); if(rows.empty()) break; cursor=store.lastRow();
                    for(const auto &r:rows) {
                        if(p.isSet("json")) jsonLine({{"type","result"},{"data",r.json()}});
                        else QTextStream(stdout)<<r.path<<": "<<outcomeText(r)<<" "<<r.signatureName<<" "<<r.reason<<Qt::endl;
                    }
                }
            } catch(const Error &e) { job.state="failed"; job.error=e.message; }
        }
        if(p.isSet("json")) jsonLine({{"type","job"},{"data",job.json()},{"exit_code",job.exitCode()}});
        else QTextStream(stdout)<<stateText(job.state)<<QStringLiteral("; проверено %1, совпадений %2, ошибок %3, пропусков %4. ").arg(job.checked).arg(job.matches).arg(job.errors).arg(job.skipped)<<job.error<<Qt::endl;
        return job.exitCode();
    } catch(const Error &e) {
        if(jsonRequested) jsonLine({{"type","error"},{"error",e.message},{"exit_code",2}});
        else QTextStream(stderr)<<e.message<<Qt::endl;
        return 2;
    }
}
