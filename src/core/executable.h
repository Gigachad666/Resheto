#pragma once
#include "file_access.h"

namespace resheto {
// Только PE32+ / ELF64 little-endian x86-64. Значение отсутствующего признака неизвестно.
struct ExecutableFeatures {
    QString format, code, reason;
    QJsonObject values;
    bool supported=false, complete=false;
};
ExecutableFeatures executableFeatures(ReadFile &file,const QString &path,const std::function<bool()> &cancel);
}
