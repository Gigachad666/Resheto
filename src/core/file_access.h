#pragma once
#include "model.h"
#include <filesystem>
namespace resheto {
std::filesystem::path nativePath(const QString &path);
QString qtPath(const std::filesystem::path &path);
bool isLinkOrReparse(const QString &path);
class ReadFile {
    struct Impl;
    std::unique_ptr<Impl> impl_;
public:
    explicit ReadFile(const QString &path);
    ~ReadFile();
    ReadFile(const ReadFile &) = delete;
    ReadFile &operator=(const ReadFile &) = delete;
    QByteArray read(qsizetype count);
    qint64 size() const;
    QString identity() const;
    bool unchanged() const;
};
}
