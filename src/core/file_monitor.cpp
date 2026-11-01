#include "file_monitor.h"
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QUuid>
#include <QHash>
#include <cstring>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <sys/inotify.h>
#include <poll.h>
#include <unistd.h>
#include <cerrno>
#endif

namespace resheto {
QJsonObject FileEvent::json() const { return {{"id",id},{"path",path},{"operation",operation},{"time",time},{"source",source}}; }
bool insideObservedRoot(const QString &path,const QString &root) {
    const auto p=absolute(path),r=absolute(root);
#ifdef _WIN32
    constexpr auto sensitivity=Qt::CaseInsensitive;
#else
    constexpr auto sensitivity=Qt::CaseSensitive;
#endif
    const auto prefix=r.endsWith('/')?r:r+"/";
    if(p.compare(r,sensitivity)!=0 && !p.startsWith(prefix,sensitivity)) return false;
    if(isLinkOrReparse(r)) return false;
    const auto relative=QDir(r).relativeFilePath(p);
    if(relative==".") return true;
    QString current=r;
    for(const auto &part:relative.split('/',Qt::SkipEmptyParts)) {
        if(part=="..") return false;
        current+="/"+part; if(isLinkOrReparse(current)) return false;
    }
    return true;
}
namespace {
FileEvent event(const QString &path,const QString &operation,const QString &source) {
    FileEvent e; e.id=QUuid::createUuid().toString(QUuid::WithoutBraces); e.path=absolute(path); e.operation=operation; e.time=now(); e.source=source; return e;
}
}
struct FileMonitor::Impl {
    QString root; bool recursive;
#ifdef _WIN32
    HANDLE directory=INVALID_HANDLE_VALUE,signal=nullptr;
    OVERLAPPED overlapped{};
    QByteArray buffer=QByteArray(65536,0);
    bool pending=false;
    void arm() {
        ResetEvent(signal); std::memset(&overlapped,0,sizeof(overlapped)); overlapped.hEvent=signal;
        if(!ReadDirectoryChangesW(directory,buffer.data(),static_cast<DWORD>(buffer.size()),recursive,
            FILE_NOTIFY_CHANGE_FILE_NAME|FILE_NOTIFY_CHANGE_DIR_NAME|FILE_NOTIFY_CHANGE_SIZE|FILE_NOTIFY_CHANGE_LAST_WRITE,
            nullptr,&overlapped,nullptr)) throw Error(QStringLiteral("ReadDirectoryChangesW: %1").arg(GetLastError()));
        pending=true;
    }
    ~Impl() {
        if(directory!=INVALID_HANDLE_VALUE) {
            if(pending) { CancelIoEx(directory,&overlapped); DWORD ignored=0; GetOverlappedResult(directory,&overlapped,&ignored,TRUE); }
            CloseHandle(directory);
        }
        if(signal) CloseHandle(signal);
    }
#else
    int fd=-1;
    QHash<int,QString> watches;
    bool initialLoss=false;
    QString initialReason;
    void addTree(const QString &path,bool rescan,FileBatch *batch=nullptr) {
        const auto relative=QDir(root).relativeFilePath(path);
        const int initialDepth=relative=="."?0:relative.split('/',Qt::SkipEmptyParts).size();
        struct Entry { QString path; int depth; }; std::vector<Entry> stack{{path,initialDepth}};
        while(!stack.empty()) {
            auto entry=std::move(stack.back()); stack.pop_back();
            if(!insideObservedRoot(entry.path,root)) continue;
            if(entry.depth>256 || watches.size()>=4096) { initialLoss=true; initialReason=QStringLiteral("Предел inotify: глубина 256 / 4096 каталогов"); break; }
            const auto encoded=QFile::encodeName(entry.path);
            const int wd=inotify_add_watch(fd,encoded.constData(),IN_CREATE|IN_MODIFY|IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE_SELF|IN_MOVE_SELF|IN_ONLYDIR|IN_DONT_FOLLOW);
            if(wd<0) { initialLoss=true; initialReason=QStringLiteral("Не удалось добавить inotify watch: ")+entry.path; continue; }
            watches[wd]=entry.path;
            if(!recursive && !rescan) continue;
            std::error_code ec;
            std::filesystem::directory_iterator it(nativePath(entry.path),ec),end;
            if(ec) { initialLoss=true; initialReason=QStringLiteral("Не удалось прочитать подкаталог наблюдения"); continue; }
            while(it!=end) {
                const auto child=qtPath(it->path()); const auto type=it->symlink_status(ec);
                if(ec) { initialLoss=true; initialReason=QStringLiteral("Ошибка перечисления дерева наблюдения"); ec.clear(); }
                else if(!std::filesystem::is_symlink(type) && insideObservedRoot(child,root)) {
                    if(recursive && std::filesystem::is_directory(type)) {
                        if(stack.size()+static_cast<size_t>(watches.size())>=4096) { initialLoss=true; initialReason=QStringLiteral("Предел дерева inotify 4096 каталогов"); break; }
                        stack.push_back({child,entry.depth+1});
                    }
                    else if(rescan && std::filesystem::is_regular_file(type) && batch) {
                        if(batch->events.size()>=4096) { initialLoss=true; initialReason=QStringLiteral("Превышен предел сверки нового поддерева"); break; }
                        batch->events.push_back(event(child,"discovered","inotify_rescan"));
                    }
                }
                it.increment(ec); if(ec) { initialLoss=true; initialReason=QStringLiteral("Ошибка продолжения дерева наблюдения"); break; }
            }
        }
    }
    ~Impl() { if(fd>=0) ::close(fd); }
#endif
};
FileMonitor::FileMonitor(const QString &directory,bool recursive) : impl_(std::make_unique<Impl>()) {
    impl_->root=absolute(directory); impl_->recursive=recursive;
    if(!QFileInfo(impl_->root).isDir() || !insideObservedRoot(impl_->root,impl_->root)) throw Error(QStringLiteral("Наблюдаемый корень недоступен либо является ссылкой"));
#ifdef _WIN32
    impl_->directory=CreateFileW(nativePath(impl_->root).c_str(),FILE_LIST_DIRECTORY,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OVERLAPPED|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(impl_->directory==INVALID_HANDLE_VALUE) throw Error(QStringLiteral("Не удалось открыть каталог наблюдения: %1").arg(GetLastError()));
    impl_->signal=CreateEventW(nullptr,TRUE,FALSE,nullptr); if(!impl_->signal) throw Error(QStringLiteral("Не удалось создать событие наблюдения"));
    impl_->arm();
#else
    impl_->fd=inotify_init1(IN_NONBLOCK|IN_CLOEXEC); if(impl_->fd<0) throw Error(QStringLiteral("Не удалось создать inotify"));
    impl_->addTree(impl_->root,false); if(impl_->watches.isEmpty()) throw Error(QStringLiteral("Нельзя наблюдать выбранный каталог inotify"));
#endif
}
FileMonitor::~FileMonitor()=default;
FileBatch FileMonitor::poll(int timeoutMs) {
    FileBatch out;
    if(timeoutMs<0 || timeoutMs>250) throw Error(QStringLiteral("Пауза FileMonitor должна быть 0..250 мс"));
    if(!QFileInfo(impl_->root).isDir() || !insideObservedRoot(impl_->root,impl_->root)) throw Error(QStringLiteral("Корень файлового наблюдения исчез/подменён"));
#ifdef _WIN32
    const DWORD state=WaitForSingleObject(impl_->signal,static_cast<DWORD>(timeoutMs));
    if(state==WAIT_TIMEOUT) return out;
    if(state!=WAIT_OBJECT_0) throw Error(QStringLiteral("Ошибка ожидания файлового события"));
    DWORD length=0;
    impl_->pending=false;
    if(!GetOverlappedResult(impl_->directory,&impl_->overlapped,&length,FALSE)) {
        const auto code=GetLastError();
        if(code==ERROR_NOTIFY_ENUM_DIR) { out.lost=true; out.reason=QStringLiteral("Потеря буфера ReadDirectoryChangesW"); }
        else throw Error(QStringLiteral("Ошибка получения файлового события: %1").arg(code));
    } else if(length==0) { out.lost=true; out.reason=QStringLiteral("Нулевая длина ReadDirectoryChangesW: возможна потеря событий"); }
    else {
        DWORD offset=0;
        while(offset<length) {
            if(length-offset<12) { out.lost=true; out.reason=QStringLiteral("Обрезанное файловое уведомление"); break; }
            const auto *n=reinterpret_cast<const FILE_NOTIFY_INFORMATION *>(impl_->buffer.constData()+offset);
            if(n->FileNameLength%2 || n->FileNameLength>length-offset-12) { out.lost=true; out.reason=QStringLiteral("Некорректное файловое уведомление"); break; }
            const auto path=QDir(impl_->root).filePath(QString::fromWCharArray(n->FileName,static_cast<int>(n->FileNameLength/2)));
            if(insideObservedRoot(path,impl_->root)) {
                if(n->Action==FILE_ACTION_ADDED || n->Action==FILE_ACTION_RENAMED_NEW_NAME) out.events.push_back(event(path,"created","ReadDirectoryChangesW"));
                else if(n->Action==FILE_ACTION_MODIFIED) out.events.push_back(event(path,"modified","ReadDirectoryChangesW"));
            }
            if(!n->NextEntryOffset) break;
            if(n->NextEntryOffset<12+n->FileNameLength || n->NextEntryOffset>length-offset) { out.lost=true; out.reason=QStringLiteral("Некорректная цепочка файловых уведомлений"); break; }
            offset+=n->NextEntryOffset;
        }
    }
    impl_->arm();
#else
    if(impl_->initialLoss) { out.lost=true; out.reason=impl_->initialReason; impl_->initialLoss=false; }
    pollfd source{impl_->fd,POLLIN,0}; const int ready=::poll(&source,1,timeoutMs);
    if(ready<0) { if(errno==EINTR) return out; throw Error(QStringLiteral("Ошибка ожидания inotify")); }
    if(ready==0) return out;
    if(source.revents & (POLLERR|POLLHUP|POLLNVAL)) throw Error(QStringLiteral("Источник inotify недоступен"));
    alignas(inotify_event) char buffer[65536]; const auto bytes=::read(impl_->fd,buffer,sizeof(buffer));
    if(bytes<0) { if(errno==EAGAIN || errno==EINTR) return out; throw Error(QStringLiteral("Ошибка чтения inotify")); }
    size_t offset=0;
    while(offset<static_cast<size_t>(bytes)) {
        if(static_cast<size_t>(bytes)-offset<sizeof(inotify_event)) { out.lost=true; out.reason=QStringLiteral("Обрезанное уведомление inotify"); break; }
        const auto *e=reinterpret_cast<const inotify_event *>(buffer+offset);
        if(e->len>static_cast<size_t>(bytes)-offset-sizeof(inotify_event)) { out.lost=true; out.reason=QStringLiteral("Некорректная длина inotify"); break; }
        if(e->mask & IN_Q_OVERFLOW) { out.lost=true; out.reason=QStringLiteral("Переполнение очереди inotify"); }
        else if(e->mask & IN_IGNORED) impl_->watches.remove(e->wd);
        else if(e->mask & (IN_DELETE_SELF|IN_MOVE_SELF)) { out.lost=true; out.reason=QStringLiteral("Наблюдаемый каталог удалён/перемещён"); inotify_rm_watch(impl_->fd,e->wd); impl_->watches.remove(e->wd); }
        else if(impl_->watches.contains(e->wd) && e->len) {
            const auto *end=static_cast<const char *>(std::memchr(e->name,0,e->len));
            if(!end) { out.lost=true; out.reason=QStringLiteral("Нет конца имени inotify"); break; }
            const auto path=QDir(impl_->watches[e->wd]).filePath(QFile::decodeName(QByteArray(e->name,static_cast<qsizetype>(end-e->name))));
            if(insideObservedRoot(path,impl_->root)) {
                if(e->mask & IN_ISDIR) {
                    if(impl_->recursive && (e->mask & (IN_CREATE|IN_MOVED_TO))) {
                        impl_->addTree(path,true,&out); out.lost=true; out.reason=QStringLiteral("Добавлено новое поддерево inotify; выполнена ограниченная сверка, события до установки watch могли быть пропущены");
                    }
                } else if(e->mask & (IN_CREATE|IN_MOVED_TO)) out.events.push_back(event(path,"created","inotify"));
                else if(e->mask & (IN_MODIFY|IN_CLOSE_WRITE)) out.events.push_back(event(path,"modified","inotify"));
            }
        }
        offset+=sizeof(inotify_event)+e->len;
    }
    if(impl_->initialLoss) { out.lost=true; out.reason=impl_->initialReason; impl_->initialLoss=false; }
#endif
    return out;
}
}
