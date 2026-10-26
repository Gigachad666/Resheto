#pragma once
#include "model.h"
namespace resheto {
constexpr qsizetype MaxPattern = 65536;
constexpr qsizetype MaxSignatureBytes = 128 * 1024 * 1024;
constexpr int MaxSignatures = 200000;
std::shared_ptr<const Snapshot> loadSignatures(const QString &path);
void createSignatures(const QString &jsonPath, const QString &databasePath);
void writeManifest(const QString &path);
}
