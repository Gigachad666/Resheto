#pragma once
#include "model.h"
namespace resheto {
// Реальный байтовый поиск; возвращает абсолютное смещение, -1 либо -2 при отмене.
qint64 findPattern(const QByteArray &window, qint64 base, qint64 firstEnd,
    const Signature &signature, const std::function<bool()> &cancel);
Result scanFile(const QString &path, const Request &request);
using Progress = std::function<void(const Job &)>;
Job runJob(Request request, Progress progress = {});
}
