#include "notifications.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QSqlError>
#ifdef RESHETO_SERVICE_NETWORK
#include "network/model.h"
#endif

namespace resheto::service {
namespace {
constexpr auto unreadCondition="NOT EXISTS (SELECT 1 FROM service_seen_detections seen WHERE seen.id=d.id)";
constexpr auto networkUnread="NOT EXISTS (SELECT 1 FROM service_seen_network seen WHERE seen.job_id=d.job_id AND seen.id=d.id)";
}

Notifications::Notifications(const QString &historyPath,bool networkHistory):db_(historyPath,false),network_(networkHistory) {
    db_.exec("CREATE TABLE IF NOT EXISTS service_seen_detections ("
             "id TEXT PRIMARY KEY REFERENCES detections(id) ON DELETE CASCADE, seen_at TEXT NOT NULL)");
    db_.exec("CREATE INDEX IF NOT EXISTS service_detection_time ON detections(time DESC,id DESC)");
    if(network_) {
        db_.exec("CREATE TABLE IF NOT EXISTS service_seen_network (job_id TEXT NOT NULL,id TEXT NOT NULL,seen_at TEXT NOT NULL,"
                 "PRIMARY KEY(job_id,id),FOREIGN KEY(job_id,id) REFERENCES network_detections(job_id,id) ON DELETE CASCADE)");
        db_.exec("CREATE INDEX IF NOT EXISTS service_network_detection_time ON network_detections(time_us DESC,job_id,id)");
    }
}

qint64 Notifications::unreadCount() {
    auto query=db_.exec(QStringLiteral("SELECT COUNT(*) FROM detections d WHERE ")+unreadCondition);
    if(!query.next())throw Error(QStringLiteral("Не удалось прочитать число непросмотренных уведомлений"));
    auto count=query.value(0).toLongLong();
    if(network_) {
        auto networkQuery=db_.exec(QStringLiteral("SELECT COUNT(*) FROM network_detections d WHERE ")+networkUnread);
        if(!networkQuery.next())throw Error(QStringLiteral("Не удалось прочитать число сетевых уведомлений"));
        count+=networkQuery.value(0).toLongLong();
    }
    return count;
}

QJsonObject Notifications::page(qint64 offset,int limit) {
    db_.transaction();
    try {
        auto count=db_.exec(network_?"SELECT (SELECT COUNT(*) FROM detections)+(SELECT COUNT(*) FROM network_detections)"
                                    :"SELECT COUNT(*) FROM detections");
        if(!count.next())throw Error(QStringLiteral("Не удалось прочитать число уведомлений"));
        const auto total=count.value(0).toLongLong();
        count.finish();
        QJsonArray rows;
        auto select=QStringLiteral("SELECT d.id,d.job_id,d.time AS time,r.data,seen.id AS seen,d.source,d.basis,"
                            "CASE WHEN d.source='behavioral' OR EXISTS(SELECT 1 FROM events e WHERE e.job_id=d.job_id "
                            "AND e.type='process_image' AND json_extract(e.details,'$.id')=json_extract(r.data,'$.event_id')) THEN 'processes' "
                            "WHEN json_extract(j.data,'$.source')='monitor' THEN 'files' ELSE 'manual' END AS view,'' AS flow_id,'' AS endpoint "
                            "FROM detections d JOIN results r ON r.row_id=d.result_id AND r.job_id=d.job_id "
                            "JOIN jobs j ON j.id=d.job_id LEFT JOIN service_seen_detections seen ON seen.id=d.id");
        if(network_)select+=QStringLiteral(" UNION ALL SELECT 'network:'||d.job_id||':'||d.id,d.job_id,"
                          "strftime('%Y-%m-%dT%H:%M:%fZ',d.time_us/1000000.0,'unixepoch'),d.data,seen.id,'network',d.basis,"
                          "'network',d.flow_id,f.endpoint FROM network_detections d "
                          "JOIN network_flows f ON f.job_id=d.job_id AND f.id=d.flow_id "
                          "LEFT JOIN service_seen_network seen ON seen.job_id=d.job_id AND seen.id=d.id");
        auto query=db_.exec(select+QStringLiteral(" ORDER BY time DESC,1 DESC LIMIT ? OFFSET ?"),{limit,offset});
        while(query.next()) {
            const auto id=query.value(0).toString(),jobId=query.value(1).toString(),time=query.value(2).toString();
            auto row=QJsonObject{{"id",id},{"job_id",jobId},{"time",time},{"view",query.value(7).toString()},
                                 {"acknowledged",!query.value(4).isNull()}};
#ifdef RESHETO_SERVICE_NETWORK
            if(row["view"]=="network") {
                const auto detection=network::Detection::fromJson(QJsonDocument::fromJson(query.value(3).toByteArray()).object());
                if(detection.flowId!=query.value(8).toString() || detection.basis!=query.value(6).toString() ||
                   id!=QStringLiteral("network:")+jobId+":"+detection.id)
                    throw Error(QStringLiteral("Сетевое уведомление не соответствует сохранённому обнаружению"));
                row["path"]=query.value(9).toString();
                row["name"]=detection.description;
                row["basis"]=detection.basis;
                row["flow_id"]=detection.flowId;
                row["detection_id"]=detection.id;
                rows.append(row);
                continue;
            }
#endif
            const auto result=Result::fromJson(QJsonDocument::fromJson(query.value(3).toByteArray()).object());
            if(!isDetection(result) || result.jobId!=jobId || result.time!=time ||
               result.source!=query.value(5).toString() || result.basis!=query.value(6).toString())
                throw Error(QStringLiteral("Строка уведомления не соответствует сохранённому результату"));
            row["path"]=result.path;
            row["name"]=detectionName(result);
            row["basis"]=result.basis;
            rows.append(row);
        }
        if(query.lastError().isValid())throw Error(query.lastError().text());
        query.finish();
        db_.commit();
        return {{"rows",rows},{"total",QString::number(total)}};
    } catch(...) {db_.rollback();throw;}
}

QJsonObject Notifications::acknowledge(const QString &id) {
    if(network_ && id.startsWith("network:")) {
        const auto parts=id.split(':');
        if(parts.size()!=3)throw Error(QStringLiteral("Некорректный идентификатор уведомления"));
        const auto jobId=parts.at(1),detectionId=parts.at(2);
        db_.exec("INSERT OR IGNORE INTO service_seen_network(job_id,id,seen_at) "
                 "SELECT job_id,id,? FROM network_detections WHERE job_id=? AND id=?",{now(),jobId,detectionId});
        auto query=db_.exec("SELECT 1 FROM service_seen_network WHERE job_id=? AND id=?",{jobId,detectionId});
        if(!query.next())throw Error(QStringLiteral("Сетевое уведомление не найдено"));
        return {{"acknowledged",true}};
    }
    db_.exec("INSERT OR IGNORE INTO service_seen_detections(id,seen_at) "
             "SELECT id,? FROM detections WHERE id=?",{now(),id});
    auto query=db_.exec("SELECT 1 FROM service_seen_detections WHERE id=?",{id});
    if(!query.next())throw Error(QStringLiteral("Уведомление не найдено"));
    return {{"acknowledged",true}};
}
}
