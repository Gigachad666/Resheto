#include "session.h"
#include "private_session.h"
#include "protocol.h"
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QLocalServer>
#include <QProcess>
#include <QTimer>

namespace resheto::network {
namespace {
struct SessionCancelled {};
qint64 sequence(const QJsonObject &object){bool good=false;const auto text=object["sequence"].toString();const auto value=text.toLongLong(&good);if(!good || value<=0 || QString::number(value)!=text)throw Error(QStringLiteral("Неверный номер сетевого сообщения"));return value;}
void version(const QJsonObject &object){if(object["version"]!=ipc::protocolVersion)throw Error(QStringLiteral("Несовместимая версия сетевого IPC"));}
}
NetworkSession::~NetworkSession(){cancel();if(thread_.joinable())thread_.join();}
bool NetworkSession::submit(NetworkRequest request) {
    {std::lock_guard lock(mutex_);if(busy_)return false;}
    request=prepareNetworkRequest(std::move(request));request.workerPath=absolute(request.workerPath);
    if(!QFileInfo(request.workerPath).isFile())throw Error(QStringLiteral("Не найден отдельный сетевой процесс: %1").arg(request.workerPath));
    if(thread_.joinable())thread_.join();auto job=newNetworkJob(request.analysis);cancel_=false;
    {std::lock_guard lock(mutex_);busy_=true;progress_=job;}
    try {thread_=std::thread([this,request=std::move(request),job=std::move(job)]() mutable {
        QEventLoop loop;QTimer::singleShot(0,&loop,[&]{run(std::move(request),std::move(job));loop.quit();});loop.exec();
    });}catch(...){std::lock_guard lock(mutex_);busy_=false;throw;}return true;
}
void NetworkSession::cancel(){cancel_=true;}
bool NetworkSession::busy()const{std::lock_guard lock(mutex_);return busy_;}
std::optional<NetworkJob> NetworkSession::progress()const{std::lock_guard lock(mutex_);return progress_;}
void NetworkSession::run(NetworkRequest request,NetworkJob job) {
    std::unique_ptr<NetworkStore> store;QProcess process;bool started=false;
    auto publish=[&]{std::lock_guard lock(mutex_);progress_=job;};
    auto stop=[&]{if(process.state()!=QProcess::NotRunning){process.terminate();if(!process.waitForFinished(1000)){process.kill();process.waitForFinished(1000);}}};
    QByteArray diagnostics;
    auto drain=[&]{diagnostics+=process.readAllStandardError();process.readAllStandardOutput();if(diagnostics.size()>65536)throw Error(QStringLiteral("Сетевой процесс превысил предел диагностического вывода"));};
    try {
        store=std::make_unique<NetworkStore>(Store::preparePath(request.storagePath));store->start(job,request.analysis.rules->document);started=true;publish();
        if(cancel_){job=store->finish(job.id,"cancelled");publish();}
        else {
            ipc::PrivateSession session;QLocalServer server;server.setSocketOptions(QLocalServer::UserAccessOption);server.setMaxPendingConnections(1);
            if(!server.listen(session.ticket().endpoint))throw Error(QStringLiteral("Не удалось открыть приватный локальный IPC: ")+server.errorString());
            process.setProgram(request.workerPath);process.setArguments({"--session",session.path()});process.setProcessChannelMode(QProcess::SeparateChannels);process.start();
            if(!process.waitForStarted(5000))throw Error(QStringLiteral("Не удалось запустить сетевой процесс: ")+process.errorString());
            QElapsedTimer handshake;handshake.start();std::unique_ptr<QLocalSocket> socket;int attempts=0;
            while(handshake.elapsed()<10000 && !socket) {
                drain();
                if(process.state()==QProcess::NotRunning)throw Error(QStringLiteral("Сетевой процесс завершился до подключения: ")+QString::fromUtf8(diagnostics).left(3000));
                if(cancel_)throw SessionCancelled{};
                if(!server.hasPendingConnections())server.waitForNewConnection(50);
                if(server.hasPendingConnections()) {
                    std::unique_ptr<QLocalSocket> candidate(server.nextPendingConnection());ipc::Channel channel(*candidate);const auto hello=channel.receive(1000);
                    if(hello && (*hello)["type"]=="hello" && (*hello)["version"]==ipc::protocolVersion && (*hello)["token"]==session.ticket().token && (*hello)["worker_pid"].toString()==QString::number(process.processId()))socket=std::move(candidate);
                    else if(++attempts>=4)throw Error(QStringLiteral("Повторные неверные подключения к сетевой сессии"));
                }
            }
            if(!socket)throw Error(QStringLiteral("Сетевой процесс не подключился за 10 секунд"));server.close();ipc::Channel channel(*socket);
            channel.send({{"type","start"},{"version",ipc::protocolVersion},{"options",ipc::optionsJson(request.analysis)}});
            qint64 expected=1;std::optional<AnalysisResult> result;QElapsedTimer activity,stopping;activity.start();
            while(!result) {
                drain();
                if(cancel_ && !stopping.isValid()) {
                    stopping.start();channel.send({{"type","cancel"},{"version",ipc::protocolVersion}});
                }
                // Даже непрерывные сообщения не продлевают остановку. Даём время
                // на запись последней порции SQLite и получение итогового ответа.
                if(stopping.isValid() && stopping.elapsed()>=30000)throw Error(QStringLiteral("Сетевой процесс не подтвердил остановку за 30 секунд"));
                const auto message=channel.receive(100);if(!message){if(activity.elapsed()>15000)throw Error(QStringLiteral("Сетевой процесс не передаёт прогресс более 15 секунд"));continue;}activity.restart();version(*message);const auto type=(*message)["type"].toString();
                if(type=="batch") {
                    if(sequence(*message)!=expected || !(*message)["batch"].isObject())throw Error(QStringLiteral("Нарушена последовательность сетевых результатов"));
                    const auto batch=ipc::parseBatch((*message)["batch"].toObject());job=store->append(job.id,batch);publish();
                    channel.send({{"type","ack"},{"version",ipc::protocolVersion},{"sequence",QString::number(expected++)},{"detections",ipc::stringArray(ipc::detectionIds(batch))}});
                } else if(type=="done" && (*message)["result"].isObject()) {
                    result=ipc::parseResult((*message)["result"].toObject());if(result->counters.json()!=job.counters.json())throw Error(QStringLiteral("Итог worker не совпадает с сохранёнными счётчиками"));
                } else throw Error(QStringLiteral("Неожиданное сообщение сетевого процесса"));
            }
            if(process.state()!=QProcess::NotRunning && !process.waitForFinished(5000))throw Error(QStringLiteral("Сетевой процесс не завершился после итогового сообщения"));drain();
            if(process.exitStatus()!=QProcess::NormalExit || process.exitCode()!=0)throw Error(QStringLiteral("Сетевой процесс аварийно завершился: ")+QString::fromUtf8(diagnostics).left(3000));
            job=store->finish(job.id,result->state,result->error,result->capture,result->backendVersion);publish();
        }
    }catch(const SessionCancelled &) {
        stop();try{job=store->finish(job.id,"cancelled");}catch(const Error &error){job.state="failed";job.error=error.message;job.updated=job.finished=now();}publish();
    }catch(const Error &error) {
        stop();QString reason=error.message;
        try {if(started)job=store->finish(job.id,"failed",reason);else{job.state="failed";job.error=reason;job.updated=job.finished=now();}}
        catch(const Error &storage){job.state="failed";job.error=reason+QStringLiteral("; ошибка записи истории: ")+storage.message;job.updated=job.finished=now();}
        publish();
    }catch(const std::exception &error){stop();const auto reason=QString::fromUtf8(error.what());try{if(started)job=store->finish(job.id,"failed",reason);else{job.state="failed";job.error=reason;job.updated=job.finished=now();}}catch(const Error &storage){job.state="failed";job.error=reason+"; "+storage.message;job.updated=job.finished=now();}publish();}
    {std::lock_guard lock(mutex_);busy_=false;}
}
}
