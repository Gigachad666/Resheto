#pragma once
#include <core/database.h>
#include <core/monitor.h>

namespace resheto::service {
struct MonitorOptions {
    QString directory,processImageDirectory,behaviorPath;
    bool recursive=true,files=true,processes=true,scanProcessImages=false;
};
struct Status {
    bool busy=false;
    std::optional<Job> job;
    QString storagePath,signaturePath,heuristicPath;
    QJsonObject diagnostics;
    qint64 unreadNotifications=0;
    bool reactionBusy=false;
    MonitorStatus monitor;
    std::optional<MonitorOptions> monitorOptions;
};

QString resultKey(const Result &result);

// Каждый синхронный вызов открывает своё локальное соединение.
// Для GUI вызывайте из фонового потока, как чтение Store.
class Client {
    friend class NetworkClient;
    QString endpoint_;
    QJsonObject call(const QJsonObject &command,int timeoutMs=10000) const;
public:
    explicit Client(QString endpoint);
    Status status() const;
    Job startScan(const QString &path,bool recursive) const;
    bool cancel(const QString &jobId) const;
    MonitorStatus startMonitor(const MonitorOptions &options) const;
    MonitorStatus monitorStatus() const;
    bool cancelMonitor(const QString &jobId) const;
    std::vector<ProcessInfo> processes() const;
    std::vector<Job> jobs(qint64 offset=0,int limit=50) const;
    std::optional<Job> getJob(const QString &id,bool recoverRunning=true) const;
    ResultPage query(const QString &id,const ResultQuery &query) const;
    std::optional<QJsonObject> observation(const QString &jobId,const QString &eventId) const;
    QJsonObject inspectProcess(const QString &jobId,const QString &key) const;
    QJsonObject terminateProcess(const QString &jobId,const QString &key) const;
    QJsonObject quarantine(const QString &jobId,const QString &key) const;
    QJsonObject quarantineItems(qint64 offset,int limit) const;
    QJsonObject restoreQuarantine(const QString &id,const QString &alternative={}) const;
    QJsonObject deleteQuarantine(const QString &id) const;
    QJsonObject notifications(qint64 offset,int limit) const;
    QJsonObject acknowledgeNotification(const QString &id) const;
    QJsonObject journal(qint64 offset,int limit,const QString &text={}) const;
};
}
