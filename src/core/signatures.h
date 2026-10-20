#pragma once
#include "model.h"
namespace resheto {
constexpr qsizetype MaxPattern = 65536;
constexpr qsizetype MaxSignatureBytes = 16 * 1024 * 1024;
constexpr int MaxSignatures = 4096;
std::shared_ptr<const Snapshot> loadSignatures(const QString &path);
void createSignatures(const QString &jsonPath, const QString &databasePath);
void writeManifest(const QString &path);
}
