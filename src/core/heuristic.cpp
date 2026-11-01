#include "heuristic.h"
#include <QFile>
#include <QJsonDocument>
#include <QSet>
#include <limits>

namespace resheto {
namespace {
void require(bool ok,const QString &reason) { if(!ok) throw Error(QStringLiteral("Некорректные эвристические правила: ")+reason); }
QString text(const QJsonObject &o,const char *key) {
    require(o[key].isString() && !o[key].toString().trimmed().isEmpty() && o[key].toString().size()<=512,QString::fromLatin1(key)); return o[key].toString();
}
int number(const QJsonObject &o,const char *key,int minimum) {
    const auto v=o[key]; const auto n=v.toDouble(-1);
    require(v.isDouble() && n>=minimum && n<=1000000 && n==static_cast<int>(n),QString::fromLatin1(key)); return static_cast<int>(n);
}
bool boolean(const QJsonObject &o,const char *key) { require(o[key].isBool(),QString::fromLatin1(key)); return o[key].toBool(); }
HeuristicCondition condition(const QJsonObject &o,int depth,int &nodes) {
    require(depth<=16 && ++nodes<=1024,QStringLiteral("превышена сложность условий"));
    HeuristicCondition c;
    if(o.contains("feature")) {
        require(o.size()==2 && o["equals"].isBool(),QStringLiteral("условие feature/equals"));
        c.operation="feature"; c.feature=text(o,"feature"); c.expected=o["equals"].toBool();
        require(QStringList{"writable_executable","entry_outside_executable","extension_mismatch"}.contains(c.feature),QStringLiteral("неизвестный признак: ")+c.feature);
    } else {
        require(o.size()==1,QStringLiteral("ожидается одна операция all/any/not"));
        c.operation=o.begin().key(); const auto v=o.begin().value();
        if(c.operation=="not") {
            require(v.isObject(),QStringLiteral("not требует объект")); c.children.push_back(condition(v.toObject(),depth+1,nodes));
        } else {
            require((c.operation=="all" || c.operation=="any") && v.isArray() && !v.toArray().isEmpty() && v.toArray().size()<=64,QStringLiteral("all/any требует непустой массив"));
            for(const auto &child:v.toArray()) { require(child.isObject(),QStringLiteral("условие должно быть объектом")); c.children.push_back(condition(child.toObject(),depth+1,nodes)); }
        }
    }
    return c;
}
enum class Truth { False,True,Unknown };
Truth evaluate(const HeuristicCondition &c,const QJsonObject &features) {
    if(c.operation=="feature") {
        if(!features[c.feature].isBool()) return Truth::Unknown;
        return features[c.feature].toBool()==c.expected ? Truth::True : Truth::False;
    }
    if(c.operation=="not") { auto r=evaluate(c.children.front(),features); return r==Truth::Unknown?r:(r==Truth::True?Truth::False:Truth::True); }
    bool unknown=false;
    for(const auto &child:c.children) {
        const auto r=evaluate(child,features); unknown|=r==Truth::Unknown;
        if(c.operation=="all" && r==Truth::False) return Truth::False;
        if(c.operation=="any" && r==Truth::True) return Truth::True;
    }
    return unknown?Truth::Unknown:(c.operation=="all"?Truth::True:Truth::False);
}
}
std::shared_ptr<const HeuristicRules> loadHeuristicRules(const QString &path) {
    QFile f(path); require(f.open(QIODevice::ReadOnly) && f.size()<=1024*1024,QStringLiteral("файл недоступен или больше 1 МиБ"));
    QJsonParseError error; const auto doc=QJsonDocument::fromJson(f.readAll(),&error);
    require(error.error==QJsonParseError::NoError && doc.isObject(),QStringLiteral("ожидается JSON-объект"));
    const auto root=doc.object(); require(root["format"]=="resheto-heuristic-v1",QStringLiteral("format"));
    auto rules=std::make_shared<HeuristicRules>(); rules->path=absolute(path); rules->version=text(root,"version"); rules->threshold=number(root,"threshold",1);
    require(root["rules"].isArray() && !root["rules"].toArray().isEmpty() && root["rules"].toArray().size()<=128,QStringLiteral("rules: 1..128"));
    QSet<QString> ids; int nodes=0; qint64 totalWeight=0;
    for(const auto &value:root["rules"].toArray()) {
        require(value.isObject(),QStringLiteral("правило должно быть объектом")); const auto o=value.toObject(); HeuristicRule r;
        r.id=text(o,"id"); require(!ids.contains(r.id),QStringLiteral("повторный id")); ids.insert(r.id);
        r.version=text(o,"version"); r.description=text(o,"description"); r.severity=text(o,"severity");
        require(QStringList{"info","warning","high"}.contains(r.severity),QStringLiteral("severity"));
        r.weight=number(o,"weight",0); r.critical=boolean(o,"critical"); r.enabled=boolean(o,"enabled");
        require(o["applies_to"].isArray() && !o["applies_to"].toArray().isEmpty(),QStringLiteral("applies_to"));
        for(const auto &format:o["applies_to"].toArray()) { require(format.isString() && (format=="PE" || format=="ELF") && !r.appliesTo.contains(format.toString()),QStringLiteral("applies_to: PE/ELF без дублей")); r.appliesTo.push_back(format.toString()); }
        require(o["condition"].isObject(),QStringLiteral("condition")); r.condition=condition(o["condition"].toObject(),0,nodes);
        totalWeight+=r.weight; require(totalWeight<=std::numeric_limits<int>::max(),QStringLiteral("переполнение суммы весов")); rules->entries.push_back(std::move(r));
    }
    bool active=false; for(const auto &r:rules->entries) active|=r.enabled; require(active,QStringLiteral("нет активных правил"));
    return rules;
}
QJsonObject HeuristicDecision::json() const {
    return {{"state",state},{"code",code},{"reason",reason},{"format",format},{"version",version},
        {"score",score},{"threshold",threshold},{"suspicious",suspicious},{"features",features},{"matched",matched}};
}
HeuristicDecision evaluateHeuristics(const ExecutableFeatures &f,const HeuristicRules &rules,const std::function<bool()> &cancel) {
    HeuristicDecision out; out.format=f.format; out.version=rules.version; out.threshold=rules.threshold; out.features=f.values;
    if(!f.supported) { out.state="not_applicable"; out.code=f.code; out.reason=f.reason; return out; }
    bool unknown=!f.complete, critical=false, applicable=false;
    for(const auto &r:rules.entries) {
        if(cancel()) { out.state="error"; out.code="cancelled"; out.reason=QStringLiteral("Эвристика отменена"); return out; }
        if(!r.enabled || !r.appliesTo.contains(f.format)) continue;
        applicable=true; const auto result=evaluate(r.condition,f.values); unknown|=result==Truth::Unknown;
        if(result!=Truth::True) continue;
        out.score+=r.weight; critical|=r.critical;
        out.matched.push_back(QJsonObject{{"id",r.id},{"version",r.version},{"description",r.description},{"severity",r.severity},{"weight",r.weight},{"critical",r.critical}});
    }
    if(!applicable) { out.state="not_applicable"; out.code="rules_not_applicable"; out.reason=QStringLiteral("Нет применимых правил для формата"); return out; }
    out.state=unknown?"partial":"complete";
    if(unknown) { out.code=f.code.isEmpty()?QStringLiteral("unknown_feature"):f.code; out.reason=f.reason.isEmpty()?QStringLiteral("Не все обязательные признаки доступны"):f.reason; }
    out.suspicious=out.score>=out.threshold || critical;
    return out;
}
}
