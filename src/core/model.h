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
class SearchIndex;
struct HeuristicRules;
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
    QString purpose="custom", source=QStringLiteral("не указан");
    qint64 hashCount=0, patternCount=0;
    std::vector<Signature> entries;
    qsizetype maxPattern = 0;
    std::shared_ptr<const SearchIndex> index;
};
struct Result {
    int formatVersion=1;
    QString jobId, path, identity, outcome = "not_checked", completeness = "none";
    QString code, reason, signatureId, signatureName, signatureVersion, basis, time, databaseVersion;
    QString analyzers;
    QString source="signature", rulesVersion, ruleId, ruleName, ruleVersion, eventId;
    QJsonObject details;
    qint64 size = -1, offset = -1;
    bool skipped = false;
    QJsonObject json() const;
    static Result fromJson(const QJsonObject &o);
};
struct Job {
    int formatVersion=1;
    QString id, path, databaseVersion, started, finished, state = "running", error;
    QString detectionPath, detectionName;
    QString source="manual", rulesVersion, behaviorVersion;
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
    QString heuristicPath, source="manual";
    bool recursive = true;
    qsizetype blockSize = 64 * 1024;
    std::shared_ptr<std::atomic_bool> cancel = std::make_shared<std::atomic_bool>(false);
    std::shared_ptr<const Snapshot> snapshot;
    std::shared_ptr<const HeuristicRules> heuristicRules;
    QString signatureError, heuristicError;
    Hooks hooks;
};
QString outcomeText(const Result &r);
bool isDetection(const Result &r);
QString detectionName(const Result &r);
QString stateText(const QString &state);
}
