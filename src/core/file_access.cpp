#include "file_access.h"
#include <QFile>
#include <QDir>
#include <cerrno>
#include <cstring>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace resheto {
std::filesystem::path nativePath(const QString &p) {
#ifdef _WIN32
    return std::filesystem::path(p.toStdWString());
#else
    return std::filesystem::path(QFile::encodeName(p).constData());
#endif
}
QString qtPath(const std::filesystem::path &p) {
#ifdef _WIN32
    return QDir::cleanPath(QDir::fromNativeSeparators(QString::fromStdWString(p.native())));
#else
    return QFile::decodeName(p.native().c_str());
#endif
}
bool isLinkOrReparse(const QString &p) {
#ifdef _WIN32
    const DWORD a=GetFileAttributesW(reinterpret_cast<LPCWSTR>(p.utf16()));
    return a!=INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    std::error_code ec; return std::filesystem::is_symlink(std::filesystem::symlink_status(nativePath(p),ec));
#endif
}
struct ReadFile::Impl {
    QString path;
#ifdef _WIN32
    HANDLE handle=INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info{};
    ~Impl() { if(handle!=INVALID_HANDLE_VALUE) CloseHandle(handle); }
    static bool same(const BY_HANDLE_FILE_INFORMATION &a,const BY_HANDLE_FILE_INFORMATION &b) {
        return a.dwVolumeSerialNumber==b.dwVolumeSerialNumber && a.nFileIndexHigh==b.nFileIndexHigh && a.nFileIndexLow==b.nFileIndexLow && a.nFileSizeHigh==b.nFileSizeHigh && a.nFileSizeLow==b.nFileSizeLow && a.ftLastWriteTime.dwLowDateTime==b.ftLastWriteTime.dwLowDateTime && a.ftLastWriteTime.dwHighDateTime==b.ftLastWriteTime.dwHighDateTime;
    }
#else
    int fd=-1;
    struct stat info{};
    ~Impl() { if(fd>=0) ::close(fd); }
    static bool same(const struct stat &a,const struct stat &b) {
        return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size && a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec && a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
    }
#endif
};
ReadFile::ReadFile(const QString &path) : impl_(std::make_unique<Impl>()) {
    impl_->path=path;
#ifdef _WIN32
    impl_->handle=CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if(impl_->handle==INVALID_HANDLE_VALUE) throw Error(QStringLiteral("Открытие файла, код Windows %1").arg(GetLastError()));
    if(!GetFileInformationByHandle(impl_->handle,&impl_->info) || GetFileType(impl_->handle)!=FILE_TYPE_DISK || (impl_->info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))) throw Error(QStringLiteral("Объект не является обычным файлом"));
#else
    impl_->fd=::open(QFile::encodeName(path).constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(impl_->fd<0) throw Error(QStringLiteral("Открытие файла: ")+QString::fromLocal8Bit(std::strerror(errno)));
    if(::fstat(impl_->fd,&impl_->info)!=0 || !S_ISREG(impl_->info.st_mode)) throw Error(QStringLiteral("Объект не является обычным файлом"));
#endif
    if(size()<0) throw Error(QStringLiteral("Размер файла вне INT64_MAX"));
}
ReadFile::~ReadFile() = default;
qint64 ReadFile::size() const {
#ifdef _WIN32
    return static_cast<qint64>((quint64(impl_->info.nFileSizeHigh)<<32)|impl_->info.nFileSizeLow);
#else
    return impl_->info.st_size;
#endif
}
QString ReadFile::identity() const {
#ifdef _WIN32
    return QString("%1:%2:%3").arg(impl_->info.dwVolumeSerialNumber).arg(impl_->info.nFileIndexHigh).arg(impl_->info.nFileIndexLow);
#else
    return QString("%1:%2").arg(quint64(impl_->info.st_dev)).arg(quint64(impl_->info.st_ino));
#endif
}
QByteArray ReadFile::read(qsizetype count) {
    QByteArray data(count,Qt::Uninitialized);
#ifdef _WIN32
    DWORD n=0;
    if(!::ReadFile(impl_->handle,data.data(),static_cast<DWORD>(count),&n,nullptr)) throw Error(QStringLiteral("Ошибка чтения, код Windows %1").arg(GetLastError()));
#else
    ssize_t n;
    do { n=::read(impl_->fd,data.data(),static_cast<size_t>(count)); } while(n<0 && errno==EINTR);
    if(n<0) throw Error(QStringLiteral("Ошибка чтения: ")+QString::fromLocal8Bit(std::strerror(errno)));
#endif
    data.resize(static_cast<qsizetype>(n)); return data;
}
bool ReadFile::unchanged() const {
#ifdef _WIN32
    BY_HANDLE_FILE_INFORMATION current{}, named{};
    if(!GetFileInformationByHandle(impl_->handle,&current) || !Impl::same(impl_->info,current)) return false;
    HANDLE h=CreateFileW(reinterpret_cast<LPCWSTR>(impl_->path.utf16()),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    if(h==INVALID_HANDLE_VALUE) return false;
    bool ok=GetFileInformationByHandle(h,&named) && !(named.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && Impl::same(impl_->info,named);
    CloseHandle(h); return ok;
#else
    struct stat current{},named{};
    return ::fstat(impl_->fd,&current)==0 && Impl::same(impl_->info,current) && ::lstat(QFile::encodeName(impl_->path).constData(),&named)==0 && S_ISREG(named.st_mode) && Impl::same(impl_->info,named);
#endif
}
}
