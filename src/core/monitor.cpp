#include "monitor.h"
#include "database.h"
#include "heuristic.h"
#include "scanner.h"
#include "signatures.h"
#include <QFileInfo>
#include <QDir>
#include <QUuid>
#include <condition_variable>
#include <thread>
#include <deque>
#include <chrono>

namespace resheto {
namespace {
qint64 monotonic() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
QString sourcesText(const MonitorRequest &r) {
    return QStringLiteral("Файлы: %1; процессы: %2; проверка файлов процессов: %3").arg(r.files?QStringLiteral("вкл"):QStringLiteral("выкл"),r.processes?QStringLiteral("вкл"):QStringLiteral("выкл"),r.scanProcessImages?QStringLiteral("вкл"):QStringLiteral("выкл"));
}
bool imageInScope(const QString &image,const QString &scope) {
    if(image.isEmpty()) return false;
    if(scope.isEmpty()) return true;
    const auto prefix=absolute(scope)+"/";
#ifdef _WIN32
    return absolute(image).startsWith(prefix,Qt::CaseInsensitive);
#else
    return absolute(image).startsWith(prefix);
#endif
}
}
struct MonitorRuntime::Impl {
    struct Work { enum Kind { File,Process,ProcessImage,Coverage } kind=File; FileEvent file; ProcessEvent process; QString message; };
    MonitorRequest request;
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::deque<Work> queue;
    std::thread collector,worker;
    std::shared_ptr<std::atomic_bool> stop=std::make_shared<std::atomic_bool>(true);
    MonitorStatus status;
    std::vector<ProcessInfo> processList;
    QString pendingLoss;
    bool prepared=false;
    bool collectorDone=false;
    bool filesAvailable=false,imagesAvailable=false;
    QStringList excluded;

    void loss(const QString &reason) {
        { std::lock_guard lock(mutex); ++status.lost; status.state="degraded"; status.reason=reason; pendingLoss=reason; }
        wake.notify_all();
    }
    void push(Work work) {
        { std::lock_guard lock(mutex);
          if(stop->load()) return;
          if(queue.size()>=static_cast<size_t>(request.queueLimit)) { ++status.lost; status.state="degraded"; status.reason=QStringLiteral("Переполнение очереди наблюдения"); pendingLoss=status.reason; }
          else queue.push_back(std::move(work));
          status.queued=static_cast<qint64>(queue.size()); }
        wake.notify_all();
    }
    bool excludedPath(const QString &path) const {
        for(const auto &p:excluded) {
#ifdef _WIN32
            if(absolute(path).compare(p,Qt::CaseInsensitive)==0) return true;
#else
            if(absolute(path)==p) return true;
#endif
            std::error_code error; if(std::filesystem::equivalent(nativePath(path),nativePath(p),error) && !error) return true;
        }
        return false;
    }
    void collect() {
        struct Completion {
            Impl *self;
            ~Completion() { { std::lock_guard lock(self->mutex); self->collectorDone=true; } self->wake.notify_all(); }
        } completion{this};
        { std::unique_lock lock(mutex); wake.wait(lock,[&]{return prepared || stop->load();}); if(stop->load()) return; }
        try {
            std::unique_ptr<FileMonitor> files;
            if(request.files && filesAvailable) {
                try { files=std::make_unique<FileMonitor>(request.directory,request.recursive); }
                catch(const Error &e) { loss(e.message); if(!request.processes) throw; }
            }
            ProcessTracker tracker;
            QSet<QString> imageSeen;
            bool imageLimitReported=false;
            const auto scope=request.processImageDirectory.isEmpty()?request.directory:request.processImageDirectory;
            auto publishProcesses=[&](const ProcessSnapshot &snapshot) {
                std::vector<ProcessInfo> scoped;
                for(const auto &p:snapshot.processes) if(imageInScope(p.image,scope)) {
                    scoped.push_back(p);
                    if(!imagesAvailable || imageSeen.contains(p.key())) continue;
                    if(imageSeen.size()>=8192) {
                        if(!imageLimitReported) { imageLimitReported=true; loss(QStringLiteral("Достигнут предел 8192 идентичностей для проверки файлов процессов; новые проверки пропущены")); }
                        continue;
                    }
                    imageSeen.insert(p.key());
                    Work w; w.kind=Work::ProcessImage; w.process.process=p; w.process.operation="image_file";
                    w.process.id=QUuid::createUuid().toString(QUuid::WithoutBraces); w.process.source="process_snapshot";
                    w.process.time=now(); w.process.monotonicMs=monotonic(); push(std::move(w));
                }
                std::lock_guard lock(mutex); processList=std::move(scoped);
            };
            if(request.processes) {
                const auto first=processSnapshot(); tracker.update(first,monotonic());
                publishProcesses(first);
                { std::lock_guard lock(mutex); if(!first.reason.isEmpty()) status.coverage+=QStringLiteral("; ")+first.reason; }
                Work coverage; coverage.kind=Work::Coverage; coverage.message=first.reason.isEmpty()?QStringLiteral("lifecycle_polling: могут быть пропущены короткоживущие процессы"):first.reason; push(std::move(coverage));
                if(!first.available) loss(first.reason);
            }
            { std::lock_guard lock(mutex); if(stop->load()) return; status.ready=true; if(status.state=="starting") status.state="running"; }
            struct Pending { FileEvent event; qint64 due; };
            QHash<QString,Pending> pending;
            qint64 nextProcesses=monotonic()+request.processIntervalMs;
            QString previousProcessWarning;
            while(!stop->load()) {
                if(files) {
                    FileBatch batch;
                    try { batch=files->poll(20); }
                    catch(const Error &e) { loss(e.message); files.reset(); if(!request.processes) { stop->store(true); wake.notify_all(); } }
                    if(batch.lost) loss(batch.reason);
                    for(auto e:batch.events) {
                        if(!insideObservedRoot(e.path,request.directory) || excludedPath(e.path) || QFileInfo(e.path).isDir()) continue;
                        const auto key=absolute(e.path);
                        if(pending.contains(key)) {
                            auto &item=pending[key]; if(item.event.operation=="created") e.operation="created";
                            item.event=std::move(e); item.due=monotonic()+request.debounceMs;
                        } else if(pending.size()<request.queueLimit) pending.insert(key,{std::move(e),monotonic()+request.debounceMs});
                        else loss(QStringLiteral("Переполнение окна объединения файловых событий"));
                    }
                } else {
                    std::unique_lock lock(mutex); wake.wait_for(lock,std::chrono::milliseconds(20),[&]{return stop->load();});
                }
                const auto tick=monotonic();
                for(auto i=pending.begin();i!=pending.end();) {
                    if(i->due>tick) { ++i; continue; }
                    Work w; w.kind=Work::File; w.file=std::move(i->event); i=pending.erase(i); push(std::move(w));
                }
                if(request.processes && tick>=nextProcesses) {
                    const auto snapshot=processSnapshot(); const auto events=tracker.update(snapshot,monotonic());
                    publishProcesses(snapshot);
                    if(!snapshot.available) loss(snapshot.reason);
                    else if(snapshot.reason!=previousProcessWarning) {
                        previousProcessWarning=snapshot.reason;
                        Work coverage; coverage.kind=Work::Coverage; coverage.message=snapshot.reason.isEmpty()?QStringLiteral("Снимок доступен; сохраняется ограниченный lifecycle_polling"):snapshot.reason; push(std::move(coverage));
                        { std::lock_guard lock(mutex); status.coverage=sourcesText(request)+(snapshot.reason.isEmpty()?QString():"; "+snapshot.reason); }
                    }
                    if(tracker.takeLoss()) loss(QStringLiteral("Переполнение памяти идентичностей процессного наблюдения"));
                    for(const auto &e:events) {
                        if(!imageInScope(e.process.image,scope) && !(e.operation=="child_start" && imageInScope(e.parent.image,scope))) continue;
                        Work w; w.kind=Work::Process; w.process=e; push(std::move(w));
                    }
                    nextProcesses=monotonic()+request.processIntervalMs;
                }
            }
        } catch(const Error &e) { loss(e.message); stop->store(true); wake.notify_all(); }
          catch(const std::exception &e) { loss(QString::fromUtf8(e.what())); stop->store(true); wake.notify_all(); }
    }
    void work() {
        Job job; job.formatVersion=2; job.id=request.id.isEmpty()?QUuid::createUuid().toString(QUuid::WithoutBraces):request.id; job.source="monitor";
        job.path=request.directory.isEmpty()?QStringLiteral("processes"):absolute(request.directory); job.started=now();
        std::unique_ptr<Store> store; bool started=false; QString gapReason,componentReason;
        try {
            Request file; file.id=job.id; file.source="file_event"; file.path=request.directory; file.signaturePath=request.signaturePath;
            file.heuristicPath=request.heuristicPath; file.storagePath=request.storagePath; file.cancel=stop; file.hooks=request.fileHooks;
            store=std::make_unique<Store>(request.storagePath); store->start(job); started=true;
            if(request.files || request.scanProcessImages) {
                if(!file.signaturePath.isEmpty()) { try { file.snapshot=loadSignatures(file.signaturePath); } catch(const Error &e) { file.signatureError=e.message; } }
                if(!file.heuristicPath.isEmpty()) { try { file.heuristicRules=loadHeuristicRules(file.heuristicPath); } catch(const Error &e) { file.heuristicError=e.message; } }
            }
            std::shared_ptr<const BehaviorRules> rules;
            QStringList componentErrors;
            if(request.processes && !request.behaviorPath.isEmpty()) {
                try { rules=loadBehaviorRules(request.behaviorPath); }
                catch(const Error &e) { componentErrors.push_back(QStringLiteral("Поведенческий анализ отключён: ")+e.message); }
            }
            std::unique_ptr<BehaviorAnalyzer> behavior; if(rules) { behavior=std::make_unique<BehaviorAnalyzer>(rules); job.behaviorVersion=rules->version; }
            const bool fileAnalyzer=file.snapshot || file.heuristicRules;
            filesAvailable=request.files && !request.directory.isEmpty() && fileAnalyzer;
            imagesAvailable=request.processes && request.scanProcessImages && fileAnalyzer;
            if(request.files && !filesAvailable) componentErrors.push_back(QStringLiteral("Файловое наблюдение отключено: нет доступного файлового анализатора; ")+file.signatureError+"; "+file.heuristicError);
            if(request.scanProcessImages && !imagesAvailable) componentErrors.push_back(QStringLiteral("Проверка файлов процессов отключена: нет доступного файлового анализатора; ")+file.signatureError+"; "+file.heuristicError);
            if(fileAnalyzer) {
                if(!file.signatureError.isEmpty()) componentErrors.push_back(file.signatureError);
                if(!file.heuristicError.isEmpty()) componentErrors.push_back(file.heuristicError);
            }
            if(!filesAvailable && !imagesAvailable && !behavior) throw Error(QStringLiteral("Нет доступного анализатора: ")+componentErrors.join("; "));
            componentReason=componentErrors.join("; ");
            if(file.snapshot) job.databaseVersion=file.snapshot->version;
            if(file.heuristicRules) job.rulesVersion=file.heuristicRules->version;
            QStringList paths{absolute(request.storagePath)};
            for(const auto &path:{request.signaturePath,request.heuristicPath,request.behaviorPath}) if(!path.isEmpty()) paths.push_back(absolute(path));
            if(file.snapshot) paths.push_back(file.snapshot->path);
            for(const auto &path:paths) for(const auto &suffix:{QString(),QString("-wal"),QString("-shm"),QString("-journal"),QString(".sha256")}) excluded.push_back(path+suffix);
            store->recordObservation(job.id,"monitor","monitor_started",job.path,{{"coverage",request.processes?"lifecycle_polling":"file_events"},{"files",request.files},{"processes",request.processes},{"scan_process_images",request.scanProcessImages},{"file_directory",request.directory},{"process_scope",request.processImageDirectory},{"process_interval_ms",request.processIntervalMs},{"queue_limit",request.queueLimit},{"debounce_ms",request.debounceMs},{"recursive",request.recursive},{"behavior_version",job.behaviorVersion},{"rules_version",job.rulesVersion}});
            for(const auto &error:componentErrors) store->recordObservation(job.id,"monitor","component_unavailable",job.path,{{"reason",error}});
            if(!componentErrors.isEmpty()) { std::lock_guard lock(mutex); status.state="degraded"; status.reason=componentErrors.join("; "); }
            { std::lock_guard lock(mutex); status.job=job; prepared=true; } wake.notify_all();
            auto append=[&](Result r) {
                r.formatVersion=2; r.jobId=job.id; r.databaseVersion=job.databaseVersion;
                if(r.source!="behavioral") r.rulesVersion=job.rulesVersion;
                Job next=job; ++next.results;
                if(r.skipped) ++next.skipped;
                else if(r.outcome=="not_checked") { if(r.code!="cancelled") ++next.errors; }
                else { ++next.checked; if(r.completeness=="partial") ++next.errors;
                    if(isDetection(r)) { ++next.matches; next.detectionPath=r.path; next.detectionName=detectionName(r); } }
                store->append(r,next); job=next;
                std::lock_guard lock(mutex); status.job=job;
                if(!r.reason.isEmpty() && !r.skipped && r.code!="cancelled") { status.state="degraded"; status.reason=r.reason; }
            };
            while(!stop->load()) {
                Work item; bool hasWork=false; QString lossReason;
                { std::unique_lock lock(mutex); wake.wait_for(lock,std::chrono::milliseconds(100),[&]{return stop->load() || !queue.empty() || !pendingLoss.isEmpty();});
                  lossReason=std::move(pendingLoss); pendingLoss.clear();
                  if(!queue.empty() && !stop->load()) { item=std::move(queue.front()); queue.pop_front(); hasWork=true; status.queued=static_cast<qint64>(queue.size()); } }
                if(!lossReason.isEmpty()) {
                    gapReason=lossReason; if(behavior) behavior->reset();
                    store->recordObservation(job.id,"monitor","observation_loss",job.path,{{"reason",lossReason}});
                }
                if(!hasWork) continue;
                if(item.kind==Work::Coverage) {
                    store->recordObservation(job.id,"process_monitor","coverage",job.path,{{"coverage","lifecycle_polling"},{"reason",item.message}});
                } else if(item.kind==Work::File) {
                    const auto &e=item.file;
                    store->recordObservation(job.id,"file_monitor","file_event",e.path,e.json());
                    Result r;
                    if(!insideObservedRoot(e.path,request.directory) || excludedPath(e.path)) {
                        r.path=e.path; r.time=now(); r.code="outside_scope"; r.reason=QStringLiteral("Путь вне области либо проходит через ссылку"); r.skipped=true;
                    } else {
                        for(int attempt=0;attempt<4;++attempt) {
                            r=scanFile(e.path,file);
                            if(r.code!="file_io" || attempt==3 || stop->load()) break;
                            std::unique_lock lock(mutex); wake.wait_for(lock,std::chrono::milliseconds(500),[&]{return stop->load();});
                            if(stop->load()) break;
                        }
                    }
                    r.eventId=e.id; append(std::move(r));
                    std::lock_guard lock(mutex); ++status.fileEvents;
                } else if(item.kind==Work::ProcessImage) {
                    const auto &e=item.process;
                    auto context=e.json(); context["coverage"]="image_file_by_path";
                    context["description"]=QStringLiteral("Проверка доступного файла процесса по пути образа");
                    store->recordObservation(job.id,"process_monitor","process_image",e.process.image,context);
                    auto error=processIdentityError(e.process);
                    Result r;
                    if(error.isEmpty()) { r=scanFile(e.process.image,file); error=processIdentityError(e.process); }
                    else { r.path=e.process.image; r.time=now(); r.code="process_unavailable"; r.reason=error; }
                    if(!error.isEmpty() && r.outcome!="not_checked") {
                        r.completeness="partial"; r.code="process_changed";
                        r.reason=QStringLiteral("Файл прочитан, но связь с наблюдаемым PID %1 (старт %2) повторно не подтверждена: %3").arg(e.process.pid).arg(e.process.startTime,error);
                    }
                    r.eventId=e.id; append(std::move(r));
                    std::lock_guard lock(mutex); ++status.processImages;
                } else {
                    const auto &e=item.process;
                    store->recordObservation(job.id,"process_monitor","process_event",e.process.image.isEmpty()?QString::number(e.process.pid):e.process.image,e.json());
                    { std::lock_guard lock(mutex); ++status.processEvents; }
                    if(!behavior) continue;
                    const auto scope=request.processImageDirectory.isEmpty()?request.directory:request.processImageDirectory;
                    if(e.operation!="child_start" || !imageInScope(e.parent.image,scope)) continue;
                    std::vector<BehaviorCandidate> candidates;
                    try { candidates=behavior->observe(e,e.monotonicMs); }
                    catch(const Error &error) { loss(error.message); behavior->reset(); continue; }
                    if(behavior->overflowed()) { loss(QStringLiteral("Переполнение окна поведенческого анализатора")); behavior->reset(); continue; }
                    for(const auto &c:candidates) {
                        Result r; r.path=c.process.image; r.identity=c.process.key(); r.size=-1; r.time=now(); r.eventId=e.id;
                        r.source="behavioral"; r.outcome="behavioral_match"; r.analyzers="BEHAVIOR"; r.rulesVersion=c.setVersion;
                        r.ruleId=c.ruleId; r.ruleName=c.description; r.ruleVersion=c.ruleVersion; r.details=c.json();
                        r.basis=QStringLiteral("PID %1, старт %2; %3 наблюдаемых дочерних процессов за %4 мс; правило %5").arg(c.process.pid).arg(c.process.startTime).arg(c.evidence.size()).arg(c.windowMs).arg(c.ruleId);
                        r.completeness=gapReason.isEmpty()?"full":"partial";
                        if(!gapReason.isEmpty()) { r.code="observation_incomplete"; r.reason=gapReason; }
                        append(std::move(r)); behavior->acknowledge(c,e.monotonicMs);
                    }
                }
            }
            job.state="cancelled"; if(job.errors || !gapReason.isEmpty() || !componentReason.isEmpty()) { job.state="failed"; job.error=gapReason.isEmpty()?componentReason:gapReason; }
        } catch(const Error &e) { job.state="failed"; job.error=e.message; stop->store(true); }
          catch(const std::exception &e) { job.state="failed"; job.error=QString::fromUtf8(e.what()); stop->store(true); }
        stop->store(true); wake.notify_all();
        QString finalLoss;
        { std::unique_lock lock(mutex); wake.wait(lock,[&]{return collectorDone;});
          finalLoss=pendingLoss;
          if(!pendingLoss.isEmpty()) { gapReason=pendingLoss; job.state="failed"; if(job.error.isEmpty()) job.error=gapReason; } }
        job.finished=now();
        if(started) {
            try {
                if(!finalLoss.isEmpty()) store->recordObservation(job.id,"monitor","observation_loss",job.path,{{"reason",finalLoss}});
                store->recordObservation(job.id,"monitor","monitor_stopped",job.path,{{"state",job.state},{"reason",job.error}});
                store->finish(job);
            } catch(const Error &e) { job.state="failed"; job.error=e.message; }
        }
        { std::lock_guard lock(mutex); status.job=job; status.active=false; status.ready=false; status.state=job.state=="failed"?"failed":"stopped";
          if(!job.error.isEmpty()) status.reason=job.error; prepared=true; queue.clear(); status.queued=0; }
        stop->store(true); wake.notify_all();
    }
};
MonitorRuntime::MonitorRuntime() : impl_(std::make_unique<Impl>()) {}
QString monitorStateText(const QString &state) {
    if(state=="starting") return QStringLiteral("Запуск");
    if(state=="running") return QStringLiteral("Работает");
    if(state=="degraded") return QStringLiteral("Ограниченное наблюдение");
    if(state=="failed") return QStringLiteral("Ошибка");
    return QStringLiteral("Остановлено");
}
MonitorRuntime::~MonitorRuntime() { cancel(); wait(); }
bool MonitorRuntime::start(MonitorRequest request) {
    std::lock_guard lifecycle(lifecycle_);
    { std::lock_guard lock(impl_->mutex); if(impl_->status.active) return false; }
    if(impl_->collector.joinable()) impl_->collector.join(); if(impl_->worker.joinable()) impl_->worker.join();
    // Совместимость прежнего process-only вызова без directory.
    if(request.directory.isEmpty() && request.processes) request.files=false;
    if(request.queueLimit<1 || request.queueLimit>1024 || request.debounceMs<50 || request.debounceMs>2000 || request.processIntervalMs<100 || request.processIntervalMs>2000 || (!request.files && !request.processes) || (request.files && request.directory.isEmpty()) || (request.scanProcessImages && !request.processes))
        throw Error(QStringLiteral("Некорректные параметры наблюдения"));
    if(!request.directory.isEmpty()) request.directory=absolute(request.directory);
    request.storagePath=Store::preparePath(request.storagePath);
    for(const auto &path:{request.signaturePath,request.heuristicPath,request.behaviorPath}) {
        if(path.isEmpty()) continue;
        std::error_code error;
        if(absolute(path)==request.storagePath || (std::filesystem::equivalent(nativePath(path),nativePath(request.storagePath),error) && !error)) throw Error(QStringLiteral("История и правила должны быть разными файлами"));
    }
    impl_->request=std::move(request); impl_->stop->store(false); impl_->excluded.clear();
    { std::lock_guard lock(impl_->mutex); impl_->status=MonitorStatus(); impl_->status.coverage=sourcesText(impl_->request); impl_->status.active=true; impl_->status.state="starting"; impl_->prepared=false; impl_->collectorDone=false; impl_->pendingLoss.clear(); impl_->queue.clear(); impl_->processList.clear(); }
    try { impl_->worker=std::thread([this]{impl_->work();}); impl_->collector=std::thread([this]{impl_->collect();}); }
    catch(...) { impl_->stop->store(true); { std::lock_guard lock(impl_->mutex); impl_->collectorDone=true; } impl_->wake.notify_all(); if(impl_->worker.joinable()) impl_->worker.join(); throw; }
    return true;
}
void MonitorRuntime::cancel() { impl_->stop->store(true); impl_->wake.notify_all(); }
void MonitorRuntime::wait() { std::lock_guard lifecycle(lifecycle_); if(impl_->collector.joinable()) impl_->collector.join(); if(impl_->worker.joinable()) impl_->worker.join(); }
MonitorStatus MonitorRuntime::status() const { std::lock_guard lock(impl_->mutex); return impl_->status; }
std::vector<ProcessInfo> MonitorRuntime::processes() const { std::lock_guard lock(impl_->mutex); return impl_->processList; }
}
