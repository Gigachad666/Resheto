#pragma once
#include "model.h"
#include <QHash>
#include <QSet>

namespace resheto {
struct ProcessInfo {
    quint64 pid=0,parentPid=0;
    QString startTime,image;
    QString key() const;
    QJsonObject json() const;
};
struct ProcessEvent {
    QString id,operation,time,source;
    qint64 monotonicMs=0;
    ProcessInfo process,parent;
    QJsonObject json() const;
};
struct ProcessSnapshot {
    std::vector<ProcessInfo> processes;
    bool available=true,complete=true;
    QString reason;
};
ProcessSnapshot processSnapshot();
// Пустая строка — PID, старт и путь всё ещё подтверждены ОС; файл памяти не читается.
QString processIdentityError(const ProcessInfo &process);
// Первый снимок задаёт базовую линию; последующие — достоверно наблюдённые изменения.
class ProcessTracker {
    QHash<quint64,ProcessInfo> previous_;
    QSet<QString> seen_;
    bool initialized_=false;
    bool lost_=false;
public:
    std::vector<ProcessEvent> update(const ProcessSnapshot &,qint64 monotonicMs);
    void reset();
    bool takeLoss() { const bool value=lost_; lost_=false; return value; }
};
}
