#include "controller.h"
namespace resheto {
Controller::Controller() : worker_([this]{loop();}) {}
Controller::~Controller() {
    { std::lock_guard lock(mutex_); quitting_=true; if(token_) *token_=true; if(pending_) *pending_->cancel=true; }
    wake_.notify_one(); worker_.join();
}
bool Controller::submit(Request r) {
    std::lock_guard lock(mutex_);
    if(quitting_ || pending_) return false;
    pending_=std::move(r); wake_.notify_one(); return true;
}
void Controller::cancel() {
    std::lock_guard lock(mutex_); if(token_) *token_=true; if(pending_) *pending_->cancel=true;
}
Job Controller::progress() const { std::lock_guard lock(mutex_); return progress_; }
bool Controller::busy() const { std::lock_guard lock(mutex_); return active_ || pending_.has_value(); }
void Controller::loop() {
    while(true) {
        Request request;
        { std::unique_lock lock(mutex_); wake_.wait(lock,[&]{return quitting_ || pending_.has_value();});
          if(quitting_) return;
          request=std::move(*pending_); pending_.reset(); active_=true; token_=request.cancel; progress_=Job(); }
        auto job=runJob(std::move(request),[this](const Job &j){std::lock_guard lock(mutex_); progress_=j;});
        { std::lock_guard lock(mutex_); progress_=job; active_=false; token_.reset(); }
    }
}
}
