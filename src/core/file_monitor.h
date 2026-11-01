#pragma once
#include "file_access.h"

namespace resheto {
struct FileEvent {
    QString id,path,operation,time,source;
    QJsonObject json() const;
};
struct FileBatch {
    std::vector<FileEvent> events;
    bool lost=false;
    QString reason;
};
// Проверяется вся цепочка от выбранного корня. Полной защиты от конкурентных гонок нет.
bool insideObservedRoot(const QString &path,const QString &root);
class FileMonitor {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit FileMonitor(const QString &directory,bool recursive=true);
    ~FileMonitor();
    FileMonitor(const FileMonitor &)=delete;
    FileMonitor &operator=(const FileMonitor &)=delete;
    FileBatch poll(int timeoutMs=20);
};
}
