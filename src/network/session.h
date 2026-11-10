#pragma once
#include "runner.h"
#include <mutex>
#include <thread>

namespace resheto::network {
// Владеет одним worker и своим потоком событий/SQLite. submit вызывает владелец;
// cancel/busy/progress доступны из других потоков. GUI читает копию прогресса.
class NetworkSession {
    mutable std::mutex mutex_;
    std::thread thread_;
    std::atomic_bool cancel_{false};
    bool busy_=false;
    std::optional<NetworkJob> progress_;
    void run(NetworkRequest request,NetworkJob job);
public:
    NetworkSession()=default;
    ~NetworkSession();
    NetworkSession(const NetworkSession &)=delete;
    NetworkSession &operator=(const NetworkSession &)=delete;
    bool submit(NetworkRequest request);
    void cancel();
    bool busy() const;
    std::optional<NetworkJob> progress() const;
};
// Точка входа отдельного worker; используется маленьким main без SQL-команд.
int networkWorkerMain(const QStringList &arguments);
}
