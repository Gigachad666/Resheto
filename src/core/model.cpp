#include "model.h"
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

namespace resheto {
QString now() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }
QString absolute(const QString &p) { return QDir::cleanPath(QFileInfo(p).absoluteFilePath()); }
namespace {
void valid(bool condition,const QString &detail) {
    if(!condition) throw Error(QStringLiteral("Некорректные сохранённые данные: ")+detail);
}
QString stringField(const QJsonObject &o,const char *key,bool nonempty=false) {
    const auto value=o[key];
    valid(value.isString(),QString::fromLatin1(key)+QStringLiteral(": обязательна строка"));
    const auto s=value.toString();
    valid(!nonempty || !s.trimmed().isEmpty(),QString::fromLatin1(key)+QStringLiteral(": пустое значение")); return s;
}
qint64 integerField(const QJsonObject &o,const char *key,qint64 minimum) {
    const auto s=stringField(o,key,true); bool ok=false;
    const auto n=s.toLongLong(&ok,10);
    static const QRegularExpression decimal("^-?[0-9]+$");
    valid(ok && decimal.match(s).hasMatch() && n>=minimum,QString::fromLatin1(key)+QStringLiteral(": недопустимое целое 64-битное значение"));
    return n;
}
QString timeField(const QJsonObject &o,const char *key,bool emptyAllowed=false) {
    const auto s=stringField(o,key,!emptyAllowed);
    static const QRegularExpression zone("(Z|[+-][0-9]{2}:[0-9]{2})$");
    valid((s.isEmpty() && emptyAllowed) || (zone.match(s).hasMatch() && QDateTime::fromString(s,Qt::ISODateWithMs).isValid()),QString::fromLatin1(key)+QStringLiteral(": ожидается время ISO 8601 с часовым поясом"));
    return s;
}
}
// 64-битные счётчики и смещения кодируются десятичными строками без потери точности JSON.
QJsonObject Result::json() const {
    return {{"job_id",jobId},{"path",path},{"identity",identity},{"outcome",outcome},
        {"completeness",completeness},{"code",code},{"reason",reason},{"signature_id",signatureId},
        {"signature_name",signatureName},{"signature_version",signatureVersion},{"basis",basis},
        {"time",time},{"database_version",databaseVersion},{"analyzers",analyzers},
        {"size",QString::number(size)},{"offset",QString::number(offset)},{"skipped",skipped}};
}
Result Result::fromJson(const QJsonObject &o) {
    Result r;
    r.jobId=stringField(o,"job_id",true); r.path=stringField(o,"path",true); r.identity=stringField(o,"identity");
    r.outcome=stringField(o,"outcome",true); r.completeness=stringField(o,"completeness",true);
    r.code=stringField(o,"code"); r.reason=stringField(o,"reason"); r.signatureId=stringField(o,"signature_id");
    r.signatureName=stringField(o,"signature_name"); r.signatureVersion=stringField(o,"signature_version");
    r.basis=stringField(o,"basis"); r.time=timeField(o,"time"); r.databaseVersion=stringField(o,"database_version");
    r.analyzers=stringField(o,"analyzers"); r.size=integerField(o,"size",-1); r.offset=integerField(o,"offset",-1);
    valid(o["skipped"].isBool(),QStringLiteral("skipped: обязателен bool")); r.skipped=o["skipped"].toBool();
    valid(r.outcome=="not_checked" || r.outcome=="no_match" || r.outcome=="signature_match",QStringLiteral("неизвестный outcome"));
    if(r.outcome=="not_checked") {
        valid(r.completeness=="none" && !r.code.isEmpty() && !r.reason.trimmed().isEmpty(),QStringLiteral("непроверенный объект: нужны none и причина/код"));
    } else {
        valid(r.completeness=="full" && !r.skipped && r.code.isEmpty() && r.reason.isEmpty(),QStringLiteral("итог завершённой проверки противоречит полноте/ошибке/пропуску"));
        valid(r.size>=0 && !r.identity.trimmed().isEmpty() && !r.databaseVersion.trimmed().isEmpty() && r.analyzers=="SHA-256,PATTERN",QStringLiteral("неполные сведения о завершённом сигнатурном маршруте"));
    }
    if(r.outcome=="signature_match") {
        valid(!r.signatureId.trimmed().isEmpty() && !r.signatureName.trimmed().isEmpty() && !r.signatureVersion.trimmed().isEmpty() && !r.basis.trimmed().isEmpty(),QStringLiteral("неполные сведения об обнаружении"));
        valid(r.offset==-1 || r.offset<r.size,QStringLiteral("смещение обнаружения вне файла"));
    } else {
        valid(r.signatureId.isEmpty() && r.signatureName.isEmpty() && r.signatureVersion.isEmpty() && r.basis.isEmpty() && r.offset==-1,QStringLiteral("сведения об обнаружении без подтверждённого совпадения"));
    }
    return r;
}
QJsonObject Job::json() const {
    return {{"id",id},{"source","manual"},{"path",path},{"database_version",databaseVersion},
        {"last_detection_path",detectionPath},{"last_detection_name",detectionName},
        {"started",started},{"finished",finished},{"state",state},{"error",error},
        {"results",QString::number(results)},{"checked",QString::number(checked)},
        {"matches",QString::number(matches)},{"errors",QString::number(errors)},{"skipped",QString::number(skipped)}};
}
Job Job::fromJson(const QJsonObject &o) {
    Job j; j.id=stringField(o,"id",true); j.path=stringField(o,"path",true); j.databaseVersion=stringField(o,"database_version");
    valid(stringField(o,"source")=="manual",QStringLiteral("неизвестный источник задания"));
    j.detectionPath=stringField(o,"last_detection_path"); j.detectionName=stringField(o,"last_detection_name");
    j.started=timeField(o,"started"); j.state=stringField(o,"state",true); j.finished=timeField(o,"finished",true);
    j.error=stringField(o,"error"); j.results=integerField(o,"results",0); j.checked=integerField(o,"checked",0);
    j.matches=integerField(o,"matches",0); j.errors=integerField(o,"errors",0); j.skipped=integerField(o,"skipped",0);
    valid(j.state=="running" || j.state=="completed" || j.state=="failed" || j.state=="cancelled",QStringLiteral("неизвестное состояние задания"));
    // Вычитание после проверок не переполняется даже у INT64_MAX. Остаток допустим для отменённых объектов.
    valid(j.matches<=j.checked && j.checked<=j.results && j.skipped<=j.results-j.checked && j.errors<=j.results-j.checked-j.skipped,QStringLiteral("противоречивые счётчики задания"));
    if(j.state=="completed") {
        valid(!j.finished.isEmpty() && j.error.isEmpty() && j.errors==0 && j.results-j.checked-j.skipped==0 && !j.databaseVersion.trimmed().isEmpty(),QStringLiteral("незавершённое/ошибочное задание объявлено успешным"));
    }
    if(j.state=="running") valid(j.finished.isEmpty() && j.error.isEmpty(),QStringLiteral("завершённое задание объявлено выполняющимся"));
    if(j.state=="cancelled") valid(!j.finished.isEmpty(),QStringLiteral("нет времени завершения отмены"));
    if(j.state=="failed") valid(j.errors>0 || !j.error.trimmed().isEmpty(),QStringLiteral("нет причины ошибочного завершения"));
    valid(j.results==0 || !j.databaseVersion.trimmed().isEmpty(),QStringLiteral("нет версии базы для сохранённых результатов"));
    valid(j.matches ? (!j.detectionPath.trimmed().isEmpty() && !j.detectionName.trimmed().isEmpty()) : (j.detectionPath.isEmpty() && j.detectionName.isEmpty()),QStringLiteral("последнее обнаружение не согласовано со счётчиком"));
    return j;
}
int Job::exitCode() const { if(state=="failed" || errors) return 2; if(state=="cancelled") return 3; return matches ? 1 : 0; }
QString outcomeText(const Result &r) {
    if(r.outcome=="signature_match") return QStringLiteral("Совпадение с сигнатурой");
    if(r.outcome=="no_match") return QStringLiteral("Совпадений не обнаружено");
    return QStringLiteral("Не проверен");
}
QString stateText(const QString &s) {
    if(s=="completed") return QStringLiteral("Завершено");
    if(s=="cancelled") return QStringLiteral("Отменено");
    if(s=="failed") return QStringLiteral("Ошибка / неполная проверка");
    return QStringLiteral("Выполняется");
}
}
