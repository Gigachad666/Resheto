#include "behavior.h"
#include <QFile>
#include <QJsonDocument>
#include <QCryptographicHash>
#include <QSet>
#include <QDateTime>
#include <QRegularExpression>

namespace resheto {
std::shared_ptr<const BehaviorRules> loadBehaviorRules(const QString &path) {
    auto require=[](bool good){if(!good) throw Error(QStringLiteral("Некорректные поведенческие правила"));};
    QFile f(path); require(f.open(QIODevice::ReadOnly) && f.size()<=65536);
    QJsonParseError error; const auto doc=QJsonDocument::fromJson(f.readAll(),&error); require(error.error==QJsonParseError::NoError && doc.isObject());
    const auto root=doc.object(); require(root["format"]=="resheto-behavior-v1" && root["version"].isString() && !root["version"].toString().trimmed().isEmpty() && root["version"].toString().size()<=256);
    require(root["rules"].isArray() && !root["rules"].toArray().isEmpty() && root["rules"].toArray().size()<=16);
    auto rules=std::make_shared<BehaviorRules>(); rules->version=root["version"].toString(); QSet<QString> ids;
    for(const auto &value:root["rules"].toArray()) {
        require(value.isObject()); const auto o=value.toObject(); BehaviorRule r;
        for(const auto *field:{"id","version","description"}) require(o[field].isString() && !o[field].toString().trimmed().isEmpty() && o[field].toString().size()<=512);
        require(o["enabled"].isBool()); r.id=o["id"].toString(); r.version=o["version"].toString(); r.description=o["description"].toString();
        require(!ids.contains(r.id)); ids.insert(r.id);
        const auto window=o["window_ms"].toDouble(-1), minimum=o["minimum_children"].toDouble(-1);
        require(o["window_ms"].isDouble() && window>=100 && window<=60000 && window==static_cast<int>(window));
        require(o["minimum_children"].isDouble() && minimum>=2 && minimum<=64 && minimum==static_cast<int>(minimum));
        r.windowMs=static_cast<int>(window); r.minimumChildren=static_cast<int>(minimum);
        if(o["enabled"].toBool()) rules->entries.push_back(std::move(r));
    }
    require(!rules->entries.empty()); return rules;
}
QJsonObject BehaviorCandidate::json() const {
    return {{"coverage","lifecycle_polling"},{"available_actions",QJsonArray{"observed_start","child_start","not_observed"}},
        {"unavailable_actions",QJsonArray{"file_write","registry_write","memory_injection","network"}},
        {"process",process.json()},{"rule_id",ruleId},{"rule_version",ruleVersion},{"version",setVersion},
        {"description",description},{"window_ms",windowMs},{"minimum_children",minimumChildren},{"events",evidence}};
}
BehaviorAnalyzer::BehaviorAnalyzer(std::shared_ptr<const BehaviorRules> rules) : rules_(std::move(rules)) { if(!rules_) throw Error(QStringLiteral("Нет поведенческих правил")); }
std::vector<BehaviorCandidate> BehaviorAnalyzer::observe(const ProcessEvent &event,qint64 tick) {
    static const QRegularExpression decimal("^[0-9]+$");
    auto identity=[&](const ProcessInfo &p) { bool good=false; const auto n=p.startTime.toULongLong(&good); return p.pid>0 && good && n>0 && decimal.match(p.startTime).hasMatch(); };
    const auto time=QDateTime::fromString(event.time,Qt::ISODateWithMs);
    if(tick<0 || tick<lastTick_ || event.monotonicMs<0 || event.monotonicMs>tick || event.monotonicMs<lastEvent_ || event.id.trimmed().isEmpty() || event.id.size()>256 || event.source.trimmed().isEmpty() || !time.isValid() || !identity(event.process) ||
       !QStringList{"observed_start","child_start","not_observed"}.contains(event.operation)) throw Error(QStringLiteral("Некорректное/немонотонное процессное событие"));
    if(event.operation=="child_start" && (!identity(event.parent) || event.parent.pid==event.process.pid || event.process.parentPid!=event.parent.pid || event.parent.startTime.toULongLong()>event.process.startTime.toULongLong()))
        throw Error(QStringLiteral("Недостоверная связь дочернего процесса"));
    for(const auto &e:events_) if(e.id==event.id && (e.process.key()!=event.process.key() || e.parent.key()!=event.parent.key())) throw Error(QStringLiteral("Идентификатор события повторно использован для другого процесса"));
    lastTick_=tick; lastEvent_=event.monotonicMs;
    std::vector<BehaviorCandidate> out; int maximum=0;
    for(const auto &r:rules_->entries) maximum=qMax(maximum,r.windowMs);
    while(!events_.empty() && tick-events_.front().monotonicMs>maximum) events_.pop_front();
    for(auto i=committed_.begin();i!=committed_.end();) { if(i.value()<tick) i=committed_.erase(i); else ++i; }
    if(event.operation!="child_start" || event.parent.pid==0 || event.parent.startTime.isEmpty()) return out;
    bool exists=false; for(const auto &e:events_) exists|=e.parent.key()==event.parent.key() && e.process.key()==event.process.key();
    if(!exists) {
        if(events_.size()>=1024) { reset(); overflow_=true; }
        events_.push_back(event);
    }
    for(const auto &r:rules_->entries) {
        BehaviorCandidate c; c.ruleId=r.id; c.ruleVersion=r.version; c.description=r.description; c.setVersion=rules_->version;
        c.process=event.parent; c.windowMs=r.windowMs; c.minimumChildren=r.minimumChildren;
        QByteArray basis=event.parent.key().toUtf8()+"|"+r.id.toUtf8()+"|";
        for(const auto &e:events_) {
            if(e.parent.key()!=event.parent.key() || tick-e.monotonicMs>r.windowMs) continue;
            c.evidence.push_back(e.json()); basis+=e.process.key().toUtf8()+";";
            if(c.evidence.size()>=r.minimumChildren) break;
        }
        if(c.evidence.size()<r.minimumChildren) continue;
        c.key=QString::fromLatin1(QCryptographicHash::hash(basis,QCryptographicHash::Sha256).toHex());
        if(!committed_.contains(c.key)) out.push_back(std::move(c));
    }
    return out;
}
void BehaviorAnalyzer::acknowledge(const BehaviorCandidate &candidate,qint64 tick) {
    if(!QRegularExpression("^[0-9a-f]{64}$").match(candidate.key).hasMatch() || tick<0 || tick<lastTick_ || candidate.windowMs<100 || candidate.windowMs>60000)
        throw Error(QStringLiteral("Некорректное подтверждение поведенческого обнаружения"));
    if(committed_.size()>=1024) { reset(); overflow_=true; }
    committed_[candidate.key]=tick+candidate.windowMs;
}
void BehaviorAnalyzer::reset() { events_.clear(); committed_.clear(); overflow_=false; lastTick_=-1; lastEvent_=-1; }
}
