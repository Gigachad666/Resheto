#pragma once
#include "model.h"
namespace resheto {
// Офлайн-подготовка; current.json атомарно выбирает неизменяемый каталог с БД/manifest.
struct ImportRequest {
    QString input, format, repository, version;
    QJsonObject provenance;
    std::function<void()> beforePublish; // Управляемый отказ на границе публикации для проверки ENOSPC.
};
QJsonObject importSnapshot(const ImportRequest &request);
QString resolveSignaturePath(const QString &path);
void activateVersion(const QString &repository,const QString &relativeDatabase);
}
