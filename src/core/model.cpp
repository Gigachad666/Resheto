#include "model.h"
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>
#include <QJsonArray>
#include <QSet>

namespace resheto {
QString now() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }
QString absolute(const QString &p) { return QDir::cleanPath(QFileInfo(p).absoluteFilePath()); }
namespace {
Result resultV2(const QJsonObject &o);
Job jobV2(const QJsonObject &o);
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
    QJsonObject o{{"job_id",jobId},{"path",path},{"identity",identity},{"outcome",outcome},
        {"completeness",completeness},{"code",code},{"reason",reason},{"signature_id",signatureId},
        {"signature_name",signatureName},{"signature_version",signatureVersion},{"basis",basis},
        {"time",time},{"database_version",databaseVersion},{"analyzers",analyzers},
        {"size",QString::number(size)},{"offset",QString::number(offset)},{"skipped",skipped}};
    if(formatVersion==2) {
        o["schema_version"]=2; o["analysis_source"]=source; o["rules_version"]=rulesVersion;
        o["rule_id"]=ruleId; o["rule_name"]=ruleName; o["rule_version"]=ruleVersion; o["details"]=details; o["event_id"]=eventId;
    }
    return o;
}
Result Result::fromJson(const QJsonObject &o) {
    if(o.contains("schema_version")) return resultV2(o);
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
    QJsonObject o{{"id",id},{"source",source},{"path",path},{"database_version",databaseVersion},
        {"last_detection_path",detectionPath},{"last_detection_name",detectionName},
        {"started",started},{"finished",finished},{"state",state},{"error",error},
        {"results",QString::number(results)},{"checked",QString::number(checked)},
        {"matches",QString::number(matches)},{"errors",QString::number(errors)},{"skipped",QString::number(skipped)}};
    if(formatVersion==2) { o["schema_version"]=2; o["rules_version"]=rulesVersion; o["behavior_version"]=behaviorVersion; }
    return o;
}
Job Job::fromJson(const QJsonObject &o) {
    if(o.contains("schema_version")) return jobV2(o);
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
namespace {
int smallInteger(const QJsonObject &o,const char *key,int minimum) {
    const auto value=o[key]; const auto n=value.toDouble(-1);
    valid(value.isDouble() && n>=minimum && n<=2147483647.0 && n==static_cast<int>(n),QString::fromLatin1(key)+": ожидается целое");
    return static_cast<int>(n);
}
void validateHeuristicDetails(const QJsonObject &d) {
    const auto state=stringField(d,"state",true);
    valid(state=="complete" || state=="partial" || state=="error" || state=="not_applicable",QStringLiteral("состояние эвристики"));
    const auto code=stringField(d,"code"),reason=stringField(d,"reason"),format=stringField(d,"format");
    valid(format.isEmpty() || format=="PE" || format=="ELF",QStringLiteral("формат эвристики")); stringField(d,"version",true);
    const int score=smallInteger(d,"score",0),threshold=smallInteger(d,"threshold",1);
    valid(d["suspicious"].isBool() && d["features"].isObject() && d["matched"].isArray(),QStringLiteral("основания эвристики"));
    const auto features=d["features"].toObject();
    for(auto i=features.begin();i!=features.end();++i)
        valid(QStringList{"writable_executable","entry_outside_executable","extension_mismatch"}.contains(i.key()) && i.value().isBool(),QStringLiteral("тип/имя признака"));
    const auto matched=d["matched"].toArray(); valid(matched.size()<=128,QStringLiteral("число правил"));
    qint64 sum=0; bool critical=false; QSet<QString> ids;
    for(const auto &item:matched) {
        valid(item.isObject(),QStringLiteral("правило-основание")); const auto r=item.toObject();
        const auto id=stringField(r,"id",true); valid(!ids.contains(id),QStringLiteral("повторное правило-основание")); ids.insert(id);
        stringField(r,"version",true); stringField(r,"description",true);
        valid(QStringList{"info","warning","high"}.contains(stringField(r,"severity",true)),QStringLiteral("severity"));
        sum+=smallInteger(r,"weight",0); valid(r["critical"].isBool(),QStringLiteral("critical")); critical|=r["critical"].toBool();
    }
    valid(sum==score && d["suspicious"].toBool()==(score>=threshold || critical),QStringLiteral("противоречивые сумма/порог/обнаружение"));
    if(state=="complete") valid(code.isEmpty() && reason.isEmpty() && !format.isEmpty(),QStringLiteral("полнота эвристики"));
    else valid(!code.isEmpty() && !reason.trimmed().isEmpty(),QStringLiteral("причина неполной эвристики"));
}
void validateProcess(const QJsonObject &p) {
    valid(integerField(p,"pid",1)>0,QStringLiteral("PID процесса")); integerField(p,"parent_pid",0);
    const auto start=stringField(p,"start_time",true); bool good=false;
    valid(start.toULongLong(&good)>0 && good && QRegularExpression("^[0-9]+$").match(start).hasMatch(),QStringLiteral("время старта процесса"));
    stringField(p,"image",true);
}
void validateBehaviorDetails(const QJsonObject &d) {
    valid(d["coverage"]=="lifecycle_polling" && d["available_actions"].isArray() && d["unavailable_actions"].isArray(),QStringLiteral("охват поведения"));
    stringField(d,"rule_id",true); stringField(d,"rule_version",true); stringField(d,"version",true); stringField(d,"description",true);
    const auto window=smallInteger(d,"window_ms",100),minimum=smallInteger(d,"minimum_children",2);
    valid(window<=60000 && minimum<=64 && d["process"].isObject() && d["events"].isArray(),QStringLiteral("окно/основания поведения"));
    const auto parent=d["process"].toObject(); validateProcess(parent);
    const auto events=d["events"].toArray(); valid(events.size()>=minimum && events.size()<=64,QStringLiteral("число событий поведения"));
    QSet<QString> children,eventIds; qint64 first=-1,last=-1;
    for(const auto &value:events) {
        valid(value.isObject(),QStringLiteral("процессное событие")); const auto e=value.toObject();
        const auto id=stringField(e,"id",true); valid(!eventIds.contains(id),QStringLiteral("повторное событие поведения")); eventIds.insert(id);
        valid(stringField(e,"operation")=="child_start",QStringLiteral("действие поведения")); timeField(e,"time"); stringField(e,"source",true);
        const auto tick=integerField(e,"monotonic_ms",0); if(first<0) first=tick; valid(tick>=last,QStringLiteral("порядок событий поведения")); last=tick;
        valid(e["process"].isObject() && e["parent"].isObject(),QStringLiteral("связь процессов")); const auto child=e["process"].toObject(),eventParent=e["parent"].toObject();
        validateProcess(child); validateProcess(eventParent);
        valid(eventParent["pid"]==parent["pid"] && eventParent["start_time"]==parent["start_time"] && child["parent_pid"]==parent["pid"] && child["pid"]!=parent["pid"] && child["start_time"].toString().toULongLong()>=parent["start_time"].toString().toULongLong(),QStringLiteral("недостоверный родитель поведения"));
        const auto key=child["pid"].toString()+":"+child["start_time"].toString(); valid(!children.contains(key),QStringLiteral("повторно учтён дочерний процесс")); children.insert(key);
    }
    valid(last-first<=window,QStringLiteral("основания вне окна поведения"));
}
Result resultV2(const QJsonObject &o) {
    valid(o["schema_version"].isDouble() && o["schema_version"].toDouble()==2,QStringLiteral("версия Result"));
    Result r; r.formatVersion=2;
    r.jobId=stringField(o,"job_id",true); r.path=stringField(o,"path",true); r.identity=stringField(o,"identity");
    r.outcome=stringField(o,"outcome",true); r.completeness=stringField(o,"completeness",true);
    r.code=stringField(o,"code"); r.reason=stringField(o,"reason"); r.signatureId=stringField(o,"signature_id");
    r.signatureName=stringField(o,"signature_name"); r.signatureVersion=stringField(o,"signature_version");
    r.basis=stringField(o,"basis"); r.time=timeField(o,"time"); r.databaseVersion=stringField(o,"database_version");
    r.analyzers=stringField(o,"analyzers"); r.size=integerField(o,"size",-1); r.offset=integerField(o,"offset",-1);
    valid(o["skipped"].isBool(),QStringLiteral("skipped")); r.skipped=o["skipped"].toBool();
    r.source=stringField(o,"analysis_source",true); r.rulesVersion=stringField(o,"rules_version");
    r.ruleId=stringField(o,"rule_id"); r.ruleName=stringField(o,"rule_name"); r.ruleVersion=stringField(o,"rule_version"); r.eventId=stringField(o,"event_id");
    valid(o["details"].isObject(),QStringLiteral("details")); r.details=o["details"].toObject();
    const bool behavioral=r.source=="behavioral";
    valid(r.source=="signature" || r.source=="heuristic" || behavioral,QStringLiteral("источник анализа"));
    valid(r.outcome=="not_checked" || r.outcome=="no_match" || r.outcome=="signature_match" || r.outcome=="heuristic_match" || r.outcome=="behavioral_match",QStringLiteral("исход v2"));
    if(r.outcome=="not_checked") valid(r.completeness=="none" && !r.code.isEmpty() && !r.reason.trimmed().isEmpty(),QStringLiteral("непроверенный объект без причины"));
    else {
        valid((r.completeness=="full" || r.completeness=="partial") && !r.skipped && (behavioral?r.size==-1:r.size>=0) && !r.identity.trimmed().isEmpty(),QStringLiteral("противоречивая полнота v2"));
        valid(behavioral?r.analyzers=="BEHAVIOR":QStringList{"SHA-256,PATTERN","HEURISTIC","SHA-256,PATTERN,HEURISTIC"}.contains(r.analyzers),QStringLiteral("анализаторы v2"));
        valid(!r.databaseVersion.trimmed().isEmpty() || !r.rulesVersion.trimmed().isEmpty(),QStringLiteral("нет версии анализаторов"));
        if(r.completeness=="full") valid(r.code.isEmpty() && r.reason.isEmpty(),QStringLiteral("ошибка полного результата"));
        else valid(!r.code.isEmpty() && !r.reason.trimmed().isEmpty(),QStringLiteral("нет причины partial"));
    }
    if(r.outcome=="signature_match") {
        valid(r.source=="signature" && r.analyzers.startsWith("SHA-256,PATTERN") && !r.databaseVersion.trimmed().isEmpty() && !r.signatureId.trimmed().isEmpty() && !r.signatureName.trimmed().isEmpty() && !r.signatureVersion.trimmed().isEmpty() && !r.basis.trimmed().isEmpty(),QStringLiteral("сигнатурное основание v2"));
        valid(r.offset==-1 || r.offset<r.size,QStringLiteral("смещение вне файла"));
    } else valid(r.signatureId.isEmpty() && r.signatureName.isEmpty() && r.signatureVersion.isEmpty() && r.offset==-1,QStringLiteral("ложные сигнатурные поля"));
    if(r.outcome=="heuristic_match") {
        valid(r.source=="heuristic" && r.analyzers.contains("HEURISTIC") && !r.rulesVersion.trimmed().isEmpty() && !r.ruleId.trimmed().isEmpty() && !r.ruleName.trimmed().isEmpty() && !r.ruleVersion.trimmed().isEmpty() && !r.basis.trimmed().isEmpty(),QStringLiteral("эвристическое основание"));
        valid(r.details["suspicious"].isBool() && r.details["suspicious"].toBool() && r.details["matched"].isArray() && !r.details["matched"].toArray().isEmpty(),QStringLiteral("эвристическое обнаружение без правил"));
    } else if(r.outcome=="behavioral_match") {
        valid(behavioral && !r.ruleId.trimmed().isEmpty() && !r.ruleName.trimmed().isEmpty() && !r.ruleVersion.trimmed().isEmpty() && !r.basis.trimmed().isEmpty() && !r.rulesVersion.trimmed().isEmpty(),QStringLiteral("поведенческое основание"));
    } else valid(r.ruleId.isEmpty() && r.ruleName.isEmpty() && r.ruleVersion.isEmpty(),QStringLiteral("поля правила без обнаружения"));
    if(!isDetection(r)) valid(r.basis.isEmpty(),QStringLiteral("основание без обнаружения"));
    if(!r.details.isEmpty()) {
        if(behavioral) {
            validateBehaviorDetails(r.details);
            valid(r.outcome=="behavioral_match" && r.details["rule_id"]==r.ruleId && r.details["rule_version"]==r.ruleVersion && r.details["version"]==r.rulesVersion,QStringLiteral("версии/правило поведения"));
            const auto process=r.details["process"].toObject(); valid(r.identity==process["pid"].toString()+":"+process["start_time"].toString() && r.path==process["image"].toString(),QStringLiteral("объект поведения"));
            return r;
        }
        validateHeuristicDetails(r.details); valid(r.details["version"]==r.rulesVersion,QStringLiteral("версия оснований"));
        const auto state=r.details["state"].toString();
        if(state=="partial" || state=="error") valid(r.completeness!="full",QStringLiteral("неполная эвристика объявлена полной"));
        if(state=="complete" || state=="partial") valid(r.analyzers.contains("HEURISTIC"),QStringLiteral("пропущен выполненный анализатор"));
        valid(r.outcome=="heuristic_match" || !r.details["suspicious"].toBool(),QStringLiteral("потеря эвристического обнаружения"));
        if(r.outcome=="heuristic_match") {
            bool present=false;
            for(const auto &item:r.details["matched"].toArray()) { const auto rule=item.toObject(); present|=rule["id"]==r.ruleId && rule["version"]==r.ruleVersion; }
            valid(present,QStringLiteral("правило обнаружения отсутствует в основаниях"));
        }
    }
    valid(!behavioral,QStringLiteral("поведение без оснований"));
    return r;
}
Job jobV2(const QJsonObject &o) {
    valid(o["schema_version"].isDouble() && o["schema_version"].toDouble()==2,QStringLiteral("версия Job"));
    Job j; j.formatVersion=2; j.id=stringField(o,"id",true); j.path=stringField(o,"path",true);
    j.source=stringField(o,"source",true); valid(j.source=="manual" || j.source=="file_event" || j.source=="monitor",QStringLiteral("источник задания v2"));
    j.databaseVersion=stringField(o,"database_version"); j.rulesVersion=stringField(o,"rules_version"); j.behaviorVersion=stringField(o,"behavior_version");
    j.detectionPath=stringField(o,"last_detection_path"); j.detectionName=stringField(o,"last_detection_name");
    j.started=timeField(o,"started"); j.finished=timeField(o,"finished",true); j.state=stringField(o,"state",true); j.error=stringField(o,"error");
    j.results=integerField(o,"results",0); j.checked=integerField(o,"checked",0); j.matches=integerField(o,"matches",0); j.errors=integerField(o,"errors",0); j.skipped=integerField(o,"skipped",0);
    valid(QStringList{"running","completed","failed","cancelled"}.contains(j.state),QStringLiteral("состояние задания v2"));
    valid(j.matches<=j.checked && j.checked<=j.results && j.skipped<=j.results-j.checked && j.errors<=j.results-j.skipped,QStringLiteral("счётчики задания v2"));
    valid(j.results==0 || !j.databaseVersion.trimmed().isEmpty() || !j.rulesVersion.trimmed().isEmpty() || !j.behaviorVersion.trimmed().isEmpty(),QStringLiteral("нет версий задания"));
    if(j.state=="completed") valid(!j.finished.isEmpty() && j.error.isEmpty() && j.errors==0 && j.results-j.checked-j.skipped==0,QStringLiteral("ложное успешное завершение v2"));
    if(j.state=="running") valid(j.finished.isEmpty() && j.error.isEmpty(),QStringLiteral("ложное выполнение v2"));
    if(j.state=="cancelled") valid(!j.finished.isEmpty(),QStringLiteral("нет времени отмены v2"));
    if(j.state=="failed") valid((j.errors>0 || !j.error.trimmed().isEmpty()) && (!j.finished.isEmpty() || !j.error.trimmed().isEmpty()),QStringLiteral("нет причины ошибки/неподтверждённого завершения v2"));
    valid(j.matches ? (!j.detectionPath.trimmed().isEmpty() && !j.detectionName.trimmed().isEmpty()) : (j.detectionPath.isEmpty() && j.detectionName.isEmpty()),QStringLiteral("последнее обнаружение v2"));
    return j;
}
}
bool isDetection(const Result &r) { return r.outcome=="signature_match" || r.outcome=="heuristic_match" || r.outcome=="behavioral_match"; }
QString detectionName(const Result &r) { return r.outcome=="signature_match"?r.signatureName:r.ruleName; }
int Job::exitCode() const { if(state=="failed" || errors) return 2; if(state=="cancelled") return 3; return matches ? 1 : 0; }
QString outcomeText(const Result &r) {
    if(r.completeness=="partial") {
        if(r.outcome=="heuristic_match") return QStringLiteral("Эвристические признаки; неполная проверка");
        if(r.outcome=="behavioral_match") return QStringLiteral("Поведенческий сценарий; наблюдение неполное");
        if(r.outcome=="no_match") return QStringLiteral("Признаки не выявлены; проверка неполная");
    }
    if(r.outcome=="signature_match") return QStringLiteral("Совпадение с сигнатурой");
    if(r.outcome=="heuristic_match") return QStringLiteral("Эвристические признаки");
    if(r.outcome=="behavioral_match") return QStringLiteral("Поведенческий сценарий");
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
