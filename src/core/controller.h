#pragma once
#include "scanner.h"
#include <condition_variable>
#include <mutex>
#include <thread>

namespace resheto {
// Один активный запрос, один ожидающий. Снимок прогресса перезаписывается, очередь UI-сигналов отсутствует.
class Controller {
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    bool quitting_=false, active_=false;
    std::optional<Request> pending_;
    std::shared_ptr<std::atomic_bool> token_;
    Job progress_;
    std::thread worker_;
    void loop();
public:
    Controller();
    ~Controller();
    bool submit(Request request);
    void cancel();
    Job progress() const;
    bool busy() const;
};
}
