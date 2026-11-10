#pragma once
#include "analyzer.h"
#include "core/database.h"
#include <QMap>

namespace resheto::network {
struct NetworkJob {
    QString id,source,input,started,updated,finished,state="running",error;
    QString rulesVersion,rulesChecksum,backendVersion;
    CaptureOptions scope;
    Counters counters;
    qint64 storedFlows=0,storedDetections=0;
    bool dropsAvailable=false;
    qint64 reportedDropped=0,reportedInterfaceDropped=0;
    std::optional<int> durationMs; // В старых записях ограничение не сохранялось.
    QJsonObject json() const;
    static NetworkJob fromJson(const QJsonObject &object);
    int exitCode() const;
};
struct NetworkBatch {
    std::vector<Flow> flows;
    std::vector<Detection> detections;
    std::vector<Diagnostic> diagnostics;
    Counters counters;
};
enum class NetworkSort { FirstTime, LastTime, Endpoint, Packets };
struct NetworkQuery {
    QString text;
    bool matchesOnly=false,descending=false;
    NetworkSort sort=NetworkSort::FirstTime;
    qint64 offset=0;
    int limit=200;
};
struct NetworkFlowRow {Flow flow;qint64 matches=0;QString rules;};
struct NetworkFlowPage {qint64 total=0;std::vector<NetworkFlowRow> rows;};
struct NetworkDetectionPage {qint64 total=0;std::vector<Detection> rows;};

// Соединение принадлежит создавшему его потоку. Сеть и прежний Store используют одну БД.
class NetworkStore {
    Database db_;
    bool present_=false;
    NetworkStore(const QString &path,bool readOnly,std::unique_lock<std::mutex> schemaLock);
    NetworkJob basicJob(const QString &id);
    std::shared_ptr<const NetworkRules> rulesForJob(const QString &id,const NetworkJob &job);
    void verifyRows(const NetworkJob &job,bool complete);
public:
    explicit NetworkStore(const QString &path,bool readOnly=false);
    void start(NetworkJob &job,const QJsonObject &rulesDocument);
    NetworkJob append(const QString &jobId,const NetworkBatch &batch);
    NetworkJob finish(const QString &jobId,const QString &state,const QString &error={},const CaptureStatistics &capture={},const QString &backendVersion={});
    std::optional<NetworkJob> getJob(const QString &id,bool recoverRunning=true);
    std::vector<NetworkJob> jobs(qint64 offset=0,int limit=50);
    NetworkFlowPage flows(const QString &jobId,const NetworkQuery &query={});
    std::optional<Flow> flow(const QString &jobId,const QString &flowId);
    NetworkDetectionPage detections(const QString &jobId,const QString &flowId={},const QString &text={},qint64 offset=0,int limit=200);
    std::vector<Diagnostic> diagnostics(const QString &jobId);
};
QString networkStateText(const NetworkJob &job);
QString networkScopeText(const NetworkJob &job);
QString networkIncompleteReason();
}
