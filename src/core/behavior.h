#pragma once
#include "process.h"
#include <QJsonArray>
#include <deque>

namespace resheto {
struct BehaviorRule { QString id,version,description; int windowMs=5000,minimumChildren=3; };
struct BehaviorRules { QString version; std::vector<BehaviorRule> entries; };
std::shared_ptr<const BehaviorRules> loadBehaviorRules(const QString &path);
struct BehaviorCandidate {
    QString key,ruleId,ruleVersion,description,setVersion;
    ProcessInfo process;
    QJsonArray evidence;
    int windowMs=0,minimumChildren=0;
    QJsonObject json() const;
};
class BehaviorAnalyzer {
    std::shared_ptr<const BehaviorRules> rules_;
    std::deque<ProcessEvent> events_;
    QHash<QString,qint64> committed_;
    bool overflow_=false;
    qint64 lastTick_=-1,lastEvent_=-1;
public:
    explicit BehaviorAnalyzer(std::shared_ptr<const BehaviorRules> rules);
    std::vector<BehaviorCandidate> observe(const ProcessEvent &event,qint64 monotonicMs);
    // Вызывается только после успешной фиксации обнаружения в Store.
    void acknowledge(const BehaviorCandidate &candidate,qint64 monotonicMs);
    void reset();
    bool overflowed() const { return overflow_; }
};
}
