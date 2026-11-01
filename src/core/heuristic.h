#pragma once
#include "executable.h"
#include <QJsonArray>
#include <QStringList>

namespace resheto {
struct HeuristicCondition {
    QString operation, feature;
    bool expected=true;
    std::vector<HeuristicCondition> children;
};
struct HeuristicRule {
    QString id,version,description,severity;
    QStringList appliesTo;
    HeuristicCondition condition;
    int weight=0;
    bool critical=false, enabled=true;
};
struct HeuristicRules {
    QString path,version;
    int threshold=0;
    std::vector<HeuristicRule> entries;
};
struct HeuristicDecision {
    QString state,code,reason,format,version;
    int score=0,threshold=0;
    bool suspicious=false;
    QJsonObject features;
    QJsonArray matched;
    QJsonObject json() const;
};
std::shared_ptr<const HeuristicRules> loadHeuristicRules(const QString &path);
HeuristicDecision evaluateHeuristics(const ExecutableFeatures &,const HeuristicRules &,const std::function<bool()> &cancel);
}
