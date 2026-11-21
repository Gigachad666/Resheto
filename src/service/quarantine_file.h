#pragma once
#include <core/model.h>
class QFile;

namespace resheto::service {
inline constexpr qint64 quarantineFileLimit=256*1024*1024;

// Только конкретный открытый обычный файл. Удаление не переоткрывает исходное имя.
class HeldFile {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit HeldFile(const QString &path,qint64 maximum=quarantineFileLimit);
    ~HeldFile();
    HeldFile(const HeldFile &)=delete;
    HeldFile &operator=(const HeldFile &)=delete;
    qint64 size() const;
    QString identity() const;
    void rewind();
    QByteArray read();
    bool unchanged() const;
    // stagePath фиксируется до вызова в журнале операций.
    void removeVerified(const QString &stagePath,const QString &expectedHash);
};

QString stagingPath(const QString &source,const QString &id);
void preparePrivateDirectory(const QString &path,bool allowCreate=false);
void protectPrivateFile(const QString &path);
void durableFlush(QFile &file);
void syncDirectory(const QString &path);
void publishNew(const QString &temporary,const QString &destination);
}
