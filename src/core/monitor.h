#pragma once
#include "behavior.h"
#include "file_monitor.h"
#include <mutex>

namespace resheto {
struct MonitorRequest {
    QString directory,signaturePath,heuristicPath,behaviorPath,storagePath;
    // Пустое значение ограничивает процессные правила образами из directory.
    QString processImageDirectory;
    bool recursive=true,processes=true;
    int queueLimit=64,debounceMs=200,processIntervalMs=250;
    Hooks fileHooks; // Управляемая граница чтения для отказных проверок, обычно пусто.
    QString id;
    bool files=true,scanProcessImages=false;
};
struct MonitorStatus {
    QString state="stopped",reason,coverage=QStringLiteral("Файловые события выбранного дерева; ограниченное наблюдение жизненного цикла процессов");
    bool active=false,ready=false;
    qint64 queued=0,lost=0,fileEvents=0,processEvents=0,processImages=0;
    Job job;
};
QString monitorStateText(const QString &state);
// Два потока: получение фактов и последовательная обработка/SQLite.
class MonitorRuntime {
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::mutex lifecycle_;
public:
    MonitorRuntime();
    ~MonitorRuntime();
    MonitorRuntime(const MonitorRuntime &)=delete;
    MonitorRuntime &operator=(const MonitorRuntime &)=delete;
    bool start(MonitorRequest request);
    void cancel();
    void wait();
    MonitorStatus status() const;
    std::vector<ProcessInfo> processes() const;
};
}
