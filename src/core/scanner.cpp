#include "scanner.h"
#include "database.h"
#include "file_access.h"
#include "signatures.h"
#include "search.h"
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QUuid>
#include <algorithm>
#include <limits>

namespace resheto {
qint64 findPattern(const QByteArray &w,qint64 base,qint64 firstEnd,const Signature &s,const std::function<bool()> &cancel) {
    const qint64 length=s.value.size();
    if(length>w.size()) return -1;
    qint64 lo=qMax<qint64>(0,firstEnd-base-length+1), hi=w.size()-length;
    if(s.offset) { lo=qMax(lo,*s.offset-base); hi=qMin(hi,*s.offset-base); }
    qsizetype anchor=0;
    if(!s.mask.isEmpty()) while(s.mask[anchor]=='0') ++anchor;
    quint64 comparisons=0;
    for(qint64 pos=lo;pos<=hi;++pos) {
        if((pos-lo)%1024==0 && cancel()) return -2;
        if(w[pos+anchor]!=s.value[anchor]) continue;
        bool equal=true;
        for(qsizetype k=0;k<length;++k) {
            if((++comparisons & 1023)==0 && cancel()) return -2;
            if((s.mask.isEmpty() || s.mask[k]=='1') && w[pos+k]!=s.value[k]) { equal=false; break; }
        }
        if(equal) return base+pos;
    }
    return -1;
}
Result scanFile(const QString &path,const Request &request) {
    Result r; r.path=path; r.jobId=request.id; r.time=now();
    if(!request.cancel || !request.snapshot || !request.snapshot->index || request.snapshot->entries.empty() || request.blockSize<4096 || request.blockSize>4*1024*1024) {
        r.code="analyzer_not_ready"; r.reason=QStringLiteral("Нет снимка базы либо некорректный размер блока"); return r;
    }
    r.databaseVersion=request.snapshot->version;
    auto cancelled=[&] { return request.cancel->load(std::memory_order_relaxed); };
    auto fail=[&](const QString &code,const QString &reason) { r.code=code; r.reason=reason; r.time=now(); return r; };
    try {
        if(cancelled()) return fail("cancelled",QStringLiteral("Проверка отменена"));
        if(request.hooks.beforeOpen) { auto e=request.hooks.beforeOpen(path); if(!e.isEmpty()) throw Error(e); }
        ReadFile file(path); r.identity=file.identity(); r.size=file.size();
        QCryptographicHash hash(QCryptographicHash::Sha256);
        QByteArray tail; qint64 consumed=0, foundOffset=-1; const Signature *found=nullptr;
        while(true) {
            if(cancelled()) return fail("cancelled",QStringLiteral("Проверка отменена"));
            QByteArray block=file.read(request.blockSize);
            if(block.isEmpty()) break;
            if(consumed>r.size-block.size()) return fail("changed",QStringLiteral("Размер файла изменился во время чтения"));
            hash.addData(block);
            const qint64 base=consumed-tail.size();
            QByteArray window=tail+block;
            if(request.hooks.afterBlock) request.hooks.afterBlock(path,consumed+block.size());
            if(request.snapshot->maxPattern && !request.snapshot->index->patterns(*request.snapshot,window,base,consumed,r.size,cancelled,found,foundOffset))
                return fail("cancelled",QStringLiteral("Поиск отменён"));
            consumed+=block.size();
            tail=window.right(qMax<qsizetype>(0,request.snapshot->maxPattern-1));
        }
        if(cancelled()) return fail("cancelled",QStringLiteral("Проверка отменена"));
        if(consumed!=r.size || !file.unchanged()) return fail("changed",QStringLiteral("Файл изменён, исчез или путь подменён во время проверки"));
        const auto digest=hash.result();
        if(!found) {
            found=request.snapshot->index->digest(*request.snapshot,digest,r.size);
        }
        r.completeness="full"; r.analyzers="SHA-256,PATTERN"; r.outcome=found ? "signature_match" : "no_match";
        if(found) {
            r.signatureId=found->id; r.signatureName=found->name; r.signatureVersion=found->version;
            r.offset=foundOffset;
            r.basis=found->kind=="HASH" ? QStringLiteral("SHA-256: ")+QString::fromLatin1(digest.toHex()) : QStringLiteral("PATTERN, абсолютное смещение %1").arg(foundOffset);
        }
        r.time=now(); return r;
    } catch(const Error &e) { return fail("file_io",e.message); }
}
Job runJob(Request req,Progress progress) {
    Job job; job.id=req.id.isEmpty() ? QUuid::createUuid().toString(QUuid::WithoutBraces) : req.id;
    req.id=job.id; job.path=absolute(req.path); job.started=now();
    std::unique_ptr<Store> store; bool started=false;
    QElapsedTimer throttle; throttle.start();
    auto report=[&](bool force=false) { if(progress && (force || throttle.elapsed()>=100)) { progress(job); throttle.restart(); } };
    auto cancelled=[&] { return req.cancel->load(std::memory_order_relaxed); };
    try {
        if(!req.cancel) throw Error(QStringLiteral("Отсутствует токен отмены"));
        if(req.blockSize<4096 || req.blockSize>4*1024*1024) throw Error(QStringLiteral("Размер блока должен быть 4096..4194304 байт"));
        std::error_code sameError;
        if(absolute(req.storagePath)==absolute(req.signaturePath) || (std::filesystem::equivalent(nativePath(req.storagePath),nativePath(req.signaturePath),sameError) && !sameError))
            throw Error(QStringLiteral("Хранилище и база сигнатур должны быть разными файлами"));
        store=std::make_unique<Store>(req.storagePath);
        store->start(job); started=true;
        req.snapshot=loadSignatures(req.signaturePath);
        job.databaseVersion=req.snapshot->version; report(true);
        auto emitResult=[&](Result r) {
            r.jobId=job.id; r.databaseVersion=job.databaseVersion; if(r.time.isEmpty()) r.time=now();
            Job next=job; ++next.results;
            if(r.skipped) ++next.skipped;
            else if(r.outcome=="not_checked") { if(r.code!="cancelled") ++next.errors; }
            else { ++next.checked; if(r.outcome=="signature_match") { ++next.matches; next.detectionPath=r.path; next.detectionName=r.signatureName; } }
            store->append(r,next); job=next; report();
        };
        auto note=[&](const QString &p,const QString &code,const QString &reason,bool skipped=false) {
            Result r; r.path=p; r.code=code; r.reason=reason; r.skipped=skipped; emitResult(r);
        };
        QStringList excluded;
        for(const auto &p:{absolute(req.storagePath),absolute(req.signaturePath),req.snapshot->path}) {
            for(const auto &suffix:{QString(),QString("-wal"),QString("-shm"),QString("-journal"),QString(".sha256")}) excluded.push_back(p+suffix);
        }
        auto isExcluded=[&](const QString &p) {
            for(const auto &e:excluded) {
#ifdef _WIN32
                if(p.compare(e,Qt::CaseInsensitive)==0) return true;
#else
                if(p==e) return true;
#endif
                std::error_code ec; if(std::filesystem::equivalent(nativePath(p),nativePath(e),ec) && !ec) return true;
            }
            return false;
        };
        using Iterator=std::filesystem::directory_iterator;
        struct DirectoryFrame { Iterator iterator; int depth; };
        std::vector<DirectoryFrame> stack;
        // Корень имеет глубину 0; разрешены каталоги 0..256 включительно.
        auto visit=[&](const QString &p,int depth) {
            if(cancelled()) return;
            if(isExcluded(p)) { note(p,"service_file",QStringLiteral("Собственный служебный файл исключён"),true); return; }
            if(isLinkOrReparse(p)) { note(p,"link",QStringLiteral("Ссылка / reparse point: переход запрещён"),true); return; }
            std::error_code ec;
            auto status=std::filesystem::symlink_status(nativePath(p),ec);
            if(ec || !std::filesystem::exists(status)) { note(p,"stat",QStringLiteral("Объект недоступен или исчез: ")+QString::fromStdString(ec.message())); return; }
            if(std::filesystem::is_regular_file(status)) { emitResult(scanFile(p,req)); return; }
            if(std::filesystem::is_directory(status)) {
                if(depth>0 && !req.recursive) { note(p,"non_recursive",QStringLiteral("Подкаталог пропущен: рекурсивность выключена"),true); return; }
                if(req.hooks.directoryDepth) req.hooks.directoryDepth(p,depth);
                if(depth>256) { note(p,"depth_limit",QStringLiteral("Превышен предел глубины 256 (корень — 0); глубина каталога %1").arg(depth)); return; }
                if(req.hooks.beforeDirectory) { const auto e=req.hooks.beforeDirectory(p); if(!e.isEmpty()) { note(p,"directory_io",e); return; } }
                Iterator it(nativePath(p),std::filesystem::directory_options::none,ec);
                if(ec) note(p,"directory_io",QStringLiteral("Ошибка чтения каталога: ")+QString::fromStdString(ec.message()));
                else if(it!=Iterator()) stack.push_back({std::move(it),depth});
                return;
            }
            note(p,"special",QStringLiteral("Необычный файл: устройства, сокеты и каналы не читаются"),true);
        };
        visit(job.path,0);
        while(!stack.empty() && !cancelled()) {
            auto path=qtPath(stack.back().iterator->path());
            auto parent=qtPath(stack.back().iterator->path().parent_path());
            const int depth=stack.back().depth+1;
            std::error_code ec; stack.back().iterator.increment(ec);
            if(ec) { note(parent,"directory_io",QStringLiteral("Ошибка продолжения обхода: ")+QString::fromStdString(ec.message())); stack.pop_back(); }
            else if(stack.back().iterator==Iterator()) stack.pop_back();
            visit(path,depth);
        }
        job.state=cancelled() ? "cancelled" : (job.errors ? "failed" : "completed");
    } catch(const Error &e) { job.state="failed"; job.error=e.message; }
      catch(const std::exception &e) { job.state="failed"; job.error=QString::fromUtf8(e.what()); }
    job.finished=now();
    if(started) {
        try { store->finish(job); }
        catch(const Error &e) { job.state="failed"; job.error=QStringLiteral("Ошибка сохранения завершения: ")+e.message; }
    }
    report(true); return job;
}
}
