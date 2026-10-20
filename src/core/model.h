#pragma once
#include <QJsonObject>
#include <QString>
#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <vector>

namespace resheto {
struct Error : std::runtime_error {
    QString message;
    explicit Error(QString s) : std::runtime_error(s.toStdString()), message(std::move(s)) {}
};
QString now();
QString absolute(const QString &path);
struct Signature {
    QString id, name, kind, version;
    QByteArray value, mask;
    std::optional<qint64> offset, minSize, maxSize;
};
struct Snapshot {
    QString path, version, checksum;
    std::vector<Signature> entries;
    qsizetype maxPattern = 0;
};
struct Result {
    QString jobId, path, identity, outcome = "not_checked", completeness = "none";
    QString code, reason, signatureId, signatureName, signatureVersion, basis, time, databaseVersion;
    QString analyzers;
    qint64 size = -1, offset = -1;
    bool skipped = false;
    QJsonObject json() const;
    static Result fromJson(const QJsonObject &o);
};
struct Job {
    QString id, path, databaseVersion, started, finished, state = "running", error;
    QString detectionPath, detectionName;
    qint64 results = 0, checked = 0, matches = 0, errors = 0, skipped = 0;
    QJsonObject json() const;
    static Job fromJson(const QJsonObject &o);
    int exitCode() const;
};
// Точки управляемых отказов и синхронизации для тестирования границы файлового доступа.
struct Hooks {
    std::function<QString(const QString &)> beforeOpen, beforeDirectory;
    std::function<void(const QString &, qint64)> afterBlock;
    std::function<void(const QString &, int)> directoryDepth;
};
struct Request {
    QString id, path, signaturePath, storagePath;
    bool recursive = true;
    qsizetype blockSize = 64 * 1024;
    std::shared_ptr<std::atomic_bool> cancel = std::make_shared<std::atomic_bool>(false);
    std::shared_ptr<const Snapshot> snapshot;
    Hooks hooks;
};
QString outcomeText(const Result &r);
QString stateText(const QString &state);
}
