#pragma once
#include "store.h"
#include "pcap.h"
#include <functional>

namespace resheto::network {
struct AnalysisOptions {
    QString source="pcap",input;
    std::shared_ptr<const NetworkRules> rules;
    CaptureOptions capture;
    // 0: live до остановки, PCAP до EOF. Положительное значение ограничивает длительность.
    int durationMs=30000;
};
struct AnalysisResult {
    QString state="completed",error,backendVersion;
    Counters counters;
    CaptureStatistics capture;
};
using BatchSink=std::function<void(const NetworkBatch &)>;
// Возврат sink означает commit. Только после него подтверждаются обнаружения.
// Используется и PCAP API, и отдельным worker; SQL/GUI в этом коде нет.
AnalysisResult analyzeNetwork(const AnalysisOptions &options,const BatchSink &sink,const std::function<bool()> &cancel={});

struct NetworkRequest {
    AnalysisOptions analysis;
    QString rulesPath,storagePath,workerPath;
};
// До открытия SQLite на запись проверяет вход, правила и тождество путей.
NetworkRequest prepareNetworkRequest(NetworkRequest request);
NetworkJob newNetworkJob(const AnalysisOptions &options);
// Синхронное внешнее подключение PCAP: не запускает CLI или процесс захвата.
NetworkJob scanNetworkPcap(NetworkRequest request,const std::atomic_bool *cancel=nullptr,const std::function<void(const NetworkJob &)> &progress={});
}
