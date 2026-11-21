#include "client.h"
#include "protocol.h"
#include "monitor_protocol.h"
#include <QElapsedTimer>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLocalSocket>
#include <QSet>

namespace resheto::service {
namespace {
constexpr int connectionTimeoutMs=750;
constexpr int reactionTimeoutMs=120000;

void check(bool valid) {
    if(!valid)throw Error(QStringLiteral("Некорректный ответ службы Решето"));
}

QString stringField(const QJsonObject &object,const char *key) {
    const auto value=object[key];
    check(value.isString());
    return value.toString();
}

std::optional<Job> optionalJob(const QJsonValue &value) {
    if(value.isNull())return {};
    check(value.isObject());
    return Job::fromJson(value.toObject());
}

QJsonArray arrayField(const QJsonObject &object,const char *key) {
    const auto value=object[key];
    check(value.isArray());
    const auto array=value.toArray();
    check(array.size()<=protocol::pageLimit);
    return array;
}
}

QString resultKey(const Result &result) {
    return QString::fromLatin1(QCryptographicHash::hash(QJsonDocument(result.json()).toJson(QJsonDocument::Compact),QCryptographicHash::Sha256).toHex());
}

Client::Client(QString endpoint):endpoint_(std::move(endpoint)) {
    if(!protocol::validEndpoint(endpoint_))throw Error(QStringLiteral("Имя службы: 1–64 латинские буквы, цифры, дефис или подчёркивание"));
}

QJsonObject Client::call(const QJsonObject &command,int timeoutMs) const {
    auto request=command;
    request.insert("version",protocol::version);
    const auto frame=protocol::frame(request,protocol::requestLimit);
    QLocalSocket socket;
    socket.setReadBufferSize(protocol::replyLimit+protocol::headerSize);
    socket.connectToServer(endpoint_);
    if(socket.state()!=QLocalSocket::ConnectedState && !socket.waitForConnected(connectionTimeoutMs))
        throw Error(QStringLiteral("Не удалось подключиться к службе Решето: ")+socket.errorString());
    if(socket.write(frame)!=frame.size())throw Error(QStringLiteral("Не удалось отправить запрос службе Решето"));

    QElapsedTimer elapsed;
    elapsed.start();
    while(socket.bytesToWrite()>0) {
        const auto remaining=timeoutMs-elapsed.elapsed();
        if(remaining<=0 || !socket.waitForBytesWritten(static_cast<int>(remaining)))
            throw Error(QStringLiteral("Служба Решето не приняла запрос: ")+socket.errorString());
    }
    QByteArray bytes;
    while(true) {
        bytes+=socket.read(protocol::replyLimit+protocol::headerSize-bytes.size());
        if(const auto reply=protocol::readFrame(bytes,protocol::replyLimit)) {
            check((*reply)["version"].isDouble() && (*reply)["version"].toDouble()==protocol::version && (*reply)["ok"].isBool());
            if(!(*reply)["ok"].toBool()) {
                const auto message=stringField(*reply,"message");
                check(reply->size()==4 && !stringField(*reply,"code").isEmpty() && !message.isEmpty());
                throw Error(message);
            }
            check(reply->size()==3 && (*reply)["result"].isObject());
            return (*reply)["result"].toObject();
        }
        if(socket.state()==QLocalSocket::UnconnectedState)
            throw Error(QStringLiteral("Служба Решето закрыла соединение до ответа"));
        const auto remaining=timeoutMs-elapsed.elapsed();
        if(remaining<=0)throw Error(timeoutMs==reactionTimeoutMs
            ? QStringLiteral("Ответ операции не получен. Проверьте журнал перед повтором.")
            : QStringLiteral("Служба Решето не ответила за 10 секунд"));
        socket.waitForReadyRead(static_cast<int>(remaining));
    }
}

Status Client::status() const {
    const auto reply=call({{"command","status"}});
    check(reply["busy"].isBool() && reply["reaction_busy"].isBool() && reply["diagnostics"].isObject());
    Status status;
    status.busy=reply["busy"].toBool();status.job=optionalJob(reply["job"]);
    status.storagePath=stringField(reply,"storage_path");status.signaturePath=stringField(reply,"signature_path");status.heuristicPath=stringField(reply,"heuristic_path");
    status.diagnostics=reply["diagnostics"].toObject();status.unreadNotifications=protocol::counter(reply["unread_notifications"]);status.reactionBusy=reply["reaction_busy"].toBool();
    check(reply["monitor"].isObject());status.monitor=protocol::decodeMonitorStatus(reply["monitor"].toObject());
    if(!reply["monitor_options"].isNull()) {
        check(reply["monitor_options"].isObject());
        status.monitorOptions=protocol::decodeMonitorOptions(reply["monitor_options"].toObject());
    }
    return status;
}

Job Client::startScan(const QString &path,bool recursive) const {
    if(path.trimmed().isEmpty())throw Error(QStringLiteral("Укажите путь для ручной проверки"));
    return Job::fromJson(call({{"command","start_scan"},{"path",absolute(path)},{"recursive",recursive}}));
}

bool Client::cancel(const QString &jobId) const {
    const auto reply=call({{"command","cancel"},{"job_id",jobId}});
    check(reply["accepted"].isBool());
    return reply["accepted"].toBool();
}

MonitorStatus Client::startMonitor(const MonitorOptions &options) const {
    auto paths=options;
    if(!paths.directory.isEmpty())paths.directory=absolute(paths.directory);
    if(!paths.processImageDirectory.isEmpty())paths.processImageDirectory=absolute(paths.processImageDirectory);
    if(!paths.behaviorPath.isEmpty())paths.behaviorPath=absolute(paths.behaviorPath);
    return protocol::decodeMonitorStatus(call({{"command","start_monitor"},{"options",protocol::encodeMonitorOptions(paths)}}));
}
MonitorStatus Client::monitorStatus() const {
    return protocol::decodeMonitorStatus(call({{"command","monitor_status"}}));
}
bool Client::cancelMonitor(const QString &jobId) const {
    const auto reply=call({{"command","cancel_monitor"},{"job_id",jobId}});
    check(reply["accepted"].isBool());return reply["accepted"].toBool();
}
std::vector<ProcessInfo> Client::processes() const {
    const auto status=monitorStatus();
    if(!status.active || status.job.id.isEmpty())return {};
    const auto reply=call({{"command","monitor_processes"},{"job_id",status.job.id}});
    check(stringField(reply,"job_id")==status.job.id && reply["processes"].isArray());
    const auto array=reply["processes"].toArray();check(array.size()<=4096);
    std::vector<ProcessInfo> processes;processes.reserve(static_cast<size_t>(array.size()));
    QSet<QString> identities;
    for(const auto &value:array){check(value.isObject());auto process=protocol::decodeProcess(value.toObject());check(!identities.contains(process.key()));identities.insert(process.key());processes.push_back(std::move(process));}
    return processes;
}

std::vector<Job> Client::jobs(qint64 offset,int limit) const {
    const auto reply=call({{"command","jobs"},{"offset",QString::number(offset)},{"limit",limit}});
    std::vector<Job> jobs;
    for(const auto &value:arrayField(reply,"jobs")) {
        check(value.isObject());
        jobs.push_back(Job::fromJson(value.toObject()));
    }
    return jobs;
}

std::optional<Job> Client::getJob(const QString &id,bool recoverRunning) const {
    const auto reply=call({{"command","get_job"},{"job_id",id},{"recover_running",recoverRunning}});
    const auto job=optionalJob(reply["job"]);
    check(!job || job->id==id);
    return job;
}

ResultPage Client::query(const QString &id,const ResultQuery &query) const {
    const auto reply=call({{"command","query"},{"job_id",id},{"query",protocol::encodeQuery(query)}});
    ResultPage page;
    page.total=protocol::counter(reply["total"]);
    page.upperRow=protocol::counter(reply["upper_row"]);
    const auto rows=arrayField(reply,"rows");
    check(rows.size()<=query.limit && rows.size()<=page.total);
    for(const auto &value:rows) {
        check(value.isObject());
        auto row=Result::fromJson(value.toObject());
        check(row.jobId==id);
        page.rows.push_back(std::move(row));
    }
    return page;
}

std::optional<QJsonObject> Client::observation(const QString &jobId,const QString &eventId) const {
    const auto reply=call({{"command","observation"},{"job_id",jobId},{"event_id",eventId}});
    const auto value=reply["event"];
    if(value.isNull())return {};
    check(value.isObject());
    return value.toObject();
}

QJsonObject Client::inspectProcess(const QString &jobId,const QString &key) const {
    return call({{"command","inspect_process"},{"job_id",jobId},{"result_key",key}});
}

QJsonObject Client::terminateProcess(const QString &jobId,const QString &key) const {
    return call({{"command","terminate_process"},{"job_id",jobId},{"result_key",key}},reactionTimeoutMs);
}

QJsonObject Client::quarantine(const QString &jobId,const QString &key) const {
    return call({{"command","quarantine"},{"job_id",jobId},{"result_key",key}},reactionTimeoutMs);
}
QJsonObject Client::quarantineItems(qint64 offset,int limit) const {
    return call({{"command","quarantine_items"},{"offset",QString::number(offset)},{"limit",limit}});
}
QJsonObject Client::restoreQuarantine(const QString &id,const QString &alternative) const {
    return call({{"command","restore_quarantine"},{"id",id},{"alternative",alternative}},reactionTimeoutMs);
}
QJsonObject Client::deleteQuarantine(const QString &id) const {
    return call({{"command","delete_quarantine"},{"id",id}},reactionTimeoutMs);
}
QJsonObject Client::notifications(qint64 offset,int limit) const {
    return call({{"command","notifications"},{"offset",QString::number(offset)},{"limit",limit}});
}
QJsonObject Client::acknowledgeNotification(const QString &id) const {
    return call({{"command","acknowledge_notification"},{"id",id}});
}
QJsonObject Client::journal(qint64 offset,int limit,const QString &text) const {
    return call({{"command","journal"},{"offset",QString::number(offset)},{"limit",limit},{"text",text}});
}
}
