#include "monitor_protocol.h"
#include "protocol.h"
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

namespace resheto::service::protocol {
namespace {
void require(bool valid) {
    if(!valid)throw Error(QStringLiteral("Некорректные данные файлового и процессного наблюдения службы"));
}
QString string(const QJsonObject &object,const char *key,int maximum,bool empty=true) {
    const auto value=object[key];
    require(value.isString());
    const auto text=value.toString();
    require(text.size()<=maximum && !text.contains(QChar(u'\0')) && (empty || !text.trimmed().isEmpty()));
    return text;
}
QString path(const QJsonObject &object,const char *key) {
    const auto text=string(object,key,4096);
    require(text.isEmpty() || (QDir::isAbsolutePath(text) && QFileInfo(text).isNativePath()));
    return text;
}
bool boolean(const QJsonObject &object,const char *key) {
    require(object[key].isBool());return object[key].toBool();
}
}
QJsonObject encodeMonitorOptions(const MonitorOptions &options) {
    const QJsonObject object{{"directory",options.directory},{"process_scope",options.processImageDirectory},{"behavior",options.behaviorPath},
        {"recursive",options.recursive},{"files",options.files},{"processes",options.processes},{"scan_process_images",options.scanProcessImages}};
    decodeMonitorOptions(object);
    return object;
}
MonitorOptions decodeMonitorOptions(const QJsonObject &object) {
    require(object.size()==7);
    MonitorOptions options;
    options.directory=path(object,"directory");options.processImageDirectory=path(object,"process_scope");options.behaviorPath=path(object,"behavior");
    options.recursive=boolean(object,"recursive");options.files=boolean(object,"files");options.processes=boolean(object,"processes");options.scanProcessImages=boolean(object,"scan_process_images");
    require((options.files || options.processes) && (!options.files || !options.directory.isEmpty()) && (!options.scanProcessImages || options.processes));
    return options;
}
QJsonObject encodeMonitorStatus(const MonitorStatus &status) {
    return {{"state",status.state},{"reason",status.reason},{"coverage",status.coverage},{"active",status.active},{"ready",status.ready},
        {"queued",QString::number(status.queued)},{"lost",QString::number(status.lost)},{"file_events",QString::number(status.fileEvents)},
        {"process_events",QString::number(status.processEvents)},{"process_images",QString::number(status.processImages)},
        {"job",status.job.id.isEmpty()?QJsonValue(QJsonValue::Null):QJsonValue(status.job.json())}};
}
MonitorStatus decodeMonitorStatus(const QJsonObject &object) {
    require(object.size()==11);
    MonitorStatus status;
    status.state=string(object,"state",32,false);status.reason=string(object,"reason",32768);status.coverage=string(object,"coverage",32768,false);
    require(QStringList{"stopped","starting","running","degraded","failed"}.contains(status.state));
    status.active=boolean(object,"active");status.ready=boolean(object,"ready");
    status.queued=counter(object["queued"]);status.lost=counter(object["lost"]);status.fileEvents=counter(object["file_events"]);
    status.processEvents=counter(object["process_events"]);status.processImages=counter(object["process_images"]);
    require(status.queued<=1024 && (!status.ready || status.active) && (status.active || !status.queued));
    require(status.active?status.state!="stopped":(status.state=="stopped" || status.state=="failed"));
    const auto job=object["job"];
    if(!job.isNull()) {
        require(job.isObject());status.job=Job::fromJson(job.toObject());
        require(status.job.formatVersion==2 && status.job.source=="monitor");
        require(status.active?status.job.state=="running":status.job.state!="running");
    } else require(!status.active);
    return status;
}
ProcessInfo decodeProcess(const QJsonObject &object) {
    require(object.size()==4);
    ProcessInfo process;
    process.pid=static_cast<quint64>(counter(object["pid"]));process.parentPid=static_cast<quint64>(counter(object["parent_pid"]));
    process.startTime=string(object,"start_time",32,false);process.image=string(object,"image",32768,false);
    require(process.pid>0 && process.pid<=0xffffffffULL && process.parentPid<=0xffffffffULL && counter(object["start_time"])>0 && QDir::isAbsolutePath(process.image));
    return process;
}
}
