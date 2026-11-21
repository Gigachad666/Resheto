#include "quarantine_file.h"
#include <core/file_access.h>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QScopeGuard>
#include <array>
#include <cstring>
#ifdef Q_OS_WIN
#define NOMINMAX
#include <windows.h>
#include <sddl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace resheto::service {
namespace {
void require(bool good,const QString &message) {
    if(!good)throw Error(message);
}
QString ioError(const QString &message) {
#ifdef Q_OS_WIN
    return message+QStringLiteral(" (Windows %1)").arg(GetLastError());
#else
    return message+": "+QString::fromLocal8Bit(std::strerror(errno));
#endif
}

void rejectLinks(const QString &path) {
    auto current=absolute(path);
    while(!current.isEmpty()) {
        require(!isLinkOrReparse(current),QStringLiteral("Путь карантина или восстановления содержит ссылку: ")+current);
        const auto parent=QFileInfo(current).absolutePath();
        if(parent==current)break;
        current=parent;
    }
}

#ifdef Q_OS_WIN
bool singleDataStream(HANDLE handle) {
    struct StreamBuffer {
        FILE_STREAM_INFO info;
        std::array<WCHAR,256> nameSpace;
    } streams{};
    if(!GetFileInformationByHandleEx(handle,FileStreamInfo,&streams,sizeof(streams)))
        return GetLastError()==ERROR_HANDLE_EOF;
    return streams.info.NextEntryOffset==0;
}

void protect(const QString &path,bool directory) {
    HANDLE token=nullptr;
    require(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token),ioError(QStringLiteral("Не удалось получить владельца карантина")));
    const std::unique_ptr<void,decltype(&CloseHandle)> tokenHandle(token,CloseHandle);
    DWORD size=0;
    GetTokenInformation(token,TokenUser,nullptr,0,&size);
    QByteArray bytes(size,0);
    require(GetTokenInformation(token,TokenUser,bytes.data(),size,&size),ioError(QStringLiteral("Не удалось получить SID владельца карантина")));
    LPWSTR sid=nullptr;
    require(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(bytes.data())->User.Sid,&sid),ioError(QStringLiteral("Не удалось подготовить права карантина")));
    const auto descriptorText=QStringLiteral("D:P(A;%1;FA;;;%2)").arg(directory?QStringLiteral("OICI"):QString(),QString::fromWCharArray(sid));
    LocalFree(sid);
    PSECURITY_DESCRIPTOR descriptor=nullptr;
    require(ConvertStringSecurityDescriptorToSecurityDescriptorW(reinterpret_cast<LPCWSTR>(descriptorText.utf16()),SDDL_REVISION_1,&descriptor,nullptr),ioError(QStringLiteral("Не удалось создать права карантина")));
    const bool good=SetFileSecurityW(nativePath(path).c_str(),DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,descriptor);
    LocalFree(descriptor);
    require(good,ioError(QStringLiteral("Не удалось ограничить права карантина")));
}
#else
int renameNew(int from,const char *name,int to,const char *target) {
    return static_cast<int>(::syscall(SYS_renameat2,from,name,to,target,1));
}
#endif
}

void preparePrivateDirectory(const QString &path,bool allowCreate) {
    rejectLinks(path);
    bool created=false;
    const auto markerPath=path+"/.resheto-quarantine-v1";
    const QByteArray markerContent="Resheto quarantine v1\n";
#ifdef Q_OS_WIN
    if(allowCreate && !QFileInfo::exists(path)) {
        require(QDir().mkdir(path),QStringLiteral("Не удалось создать каталог карантина: ")+path);
        created=true;
    }
    require(QFileInfo(path).isDir(),QStringLiteral("Вместо каталога карантина найден файл"));
#else
    const auto bytes=QFile::encodeName(path);
    if(allowCreate) {
        created=::mkdir(bytes.constData(),0700)==0;
        if(!created && errno!=EEXIST)throw Error(ioError(QStringLiteral("Не удалось создать каталог карантина")));
    }
    struct stat info{};
    require(::lstat(bytes.constData(),&info)==0 && S_ISDIR(info.st_mode) && info.st_uid==::geteuid(),QStringLiteral("Каталог карантина принадлежит другому пользователю или заменён"));
    require((info.st_mode&0077)==0,QStringLiteral("Каталог карантина доступен другим пользователям"));
#endif
    QFile marker(markerPath);
    if(created) {
#ifdef Q_OS_WIN
        protect(path,true);
#endif
        require(marker.open(QIODevice::WriteOnly|QIODevice::NewOnly) && marker.write(markerContent)==markerContent.size(),
                QStringLiteral("Не удалось пометить каталог карантина"));
        durableFlush(marker);
        syncDirectory(path);
    } else {
        require(!isLinkOrReparse(markerPath) && QFileInfo(marker).isFile() && marker.open(QIODevice::ReadOnly) &&
                marker.read(markerContent.size()+1)==markerContent,
                QStringLiteral("Каталог карантина занят или создан другой программой"));
    }
}

void protectPrivateFile(const QString &path) {
#ifdef Q_OS_WIN
    protect(path,false);
#else
    require(::chmod(QFile::encodeName(path).constData(),0600)==0,ioError(QStringLiteral("Не удалось ограничить права файла карантина")));
#endif
}

void durableFlush(QFile &file) {
    require(file.flush(),QStringLiteral("Не удалось записать все байты файла"));
#ifdef Q_OS_WIN
    require(FlushFileBuffers(reinterpret_cast<HANDLE>(_get_osfhandle(file.handle()))),ioError(QStringLiteral("Не удалось подтвердить запись файла")));
#else
    require(::fsync(file.handle())==0,ioError(QStringLiteral("Не удалось подтвердить запись файла")));
#endif
}

void syncDirectory(const QString &path) {
#ifndef Q_OS_WIN
    const int fd=::open(QFile::encodeName(path).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    require(fd>=0,ioError(QStringLiteral("Не удалось открыть каталог для подтверждения записи")));
    const bool good=::fsync(fd)==0;
    ::close(fd);
    require(good,ioError(QStringLiteral("Не удалось подтвердить запись каталога")));
#else
    Q_UNUSED(path);
#endif
}

void publishNew(const QString &temporary,const QString &destination) {
    rejectLinks(QFileInfo(destination).absolutePath());
#ifdef Q_OS_WIN
    require(MoveFileExW(nativePath(temporary).c_str(),nativePath(destination).c_str(),MOVEFILE_WRITE_THROUGH),ioError(QStringLiteral("Не удалось опубликовать файл без перезаписи")));
#else
    require(renameNew(AT_FDCWD,QFile::encodeName(temporary).constData(),AT_FDCWD,QFile::encodeName(destination).constData())==0,
            ioError(QStringLiteral("Не удалось опубликовать файл без перезаписи")));
    syncDirectory(QFileInfo(destination).absolutePath());
#endif
}

QString stagingPath(const QString &source,const QString &id) {
    return QFileInfo(source).absolutePath()+"/.resheto-quarantine-"+id;
}

struct HeldFile::Impl {
    QString path;
#ifdef Q_OS_WIN
    HANDLE handle=INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION info{};
    ~Impl(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    bool same(const BY_HANDLE_FILE_INFORMATION &value) const {
        return info.dwVolumeSerialNumber==value.dwVolumeSerialNumber && info.nFileIndexHigh==value.nFileIndexHigh && info.nFileIndexLow==value.nFileIndexLow &&
               info.nFileSizeHigh==value.nFileSizeHigh && info.nFileSizeLow==value.nFileSizeLow && value.nNumberOfLinks==1 &&
               info.ftLastWriteTime.dwLowDateTime==value.ftLastWriteTime.dwLowDateTime && info.ftLastWriteTime.dwHighDateTime==value.ftLastWriteTime.dwHighDateTime;
    }
#else
    int fd=-1,parent=-1;
    QByteArray name;
    struct stat info{};
    ~Impl(){if(fd>=0)::close(fd);if(parent>=0)::close(parent);}
    bool same(const struct stat &value) const {
        return info.st_dev==value.st_dev && info.st_ino==value.st_ino && info.st_size==value.st_size && value.st_nlink==1 &&
               info.st_mtim.tv_sec==value.st_mtim.tv_sec && info.st_mtim.tv_nsec==value.st_mtim.tv_nsec;
    }
#endif
};

HeldFile::HeldFile(const QString &path,qint64 maximum):impl_(std::make_unique<Impl>()) {
    impl_->path=path;
    rejectLinks(path);
#ifdef Q_OS_WIN
    require(!path.mid(2).contains(':'),QStringLiteral("Карантин принимает только основной поток файла"));
    impl_->handle=CreateFileW(nativePath(path).c_str(),GENERIC_READ|DELETE,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    require(impl_->handle!=INVALID_HANDLE_VALUE,ioError(QStringLiteral("Не удалось открыть файл с защитой от замены")));
    require(GetFileInformationByHandle(impl_->handle,&impl_->info) && GetFileType(impl_->handle)==FILE_TYPE_DISK &&
            !(impl_->info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) && impl_->info.nNumberOfLinks==1,
            QStringLiteral("Требуется обычный файл без ссылок и других жёстких имён"));
    require(singleDataStream(impl_->handle),QStringLiteral("Файл содержит дополнительные потоки, или их не удалось проверить"));
#else
    impl_->parent=::open(QFile::encodeName(QFileInfo(path).absolutePath()).constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    require(impl_->parent>=0,ioError(QStringLiteral("Не удалось открыть каталог исходного файла")));
    impl_->name=QFile::encodeName(QFileInfo(path).fileName());
    impl_->fd=::openat(impl_->parent,impl_->name.constData(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    require(impl_->fd>=0,ioError(QStringLiteral("Не удалось открыть исходный файл")));
    require(::fstat(impl_->fd,&impl_->info)==0 && S_ISREG(impl_->info.st_mode) && impl_->info.st_nlink==1,
            QStringLiteral("Требуется обычный файл без ссылок и других жёстких имён"));
#endif
    require(size()>=0 && size()<=maximum,QStringLiteral("Карантин принимает файлы размером до 256 МиБ"));
}

HeldFile::~HeldFile()=default;
qint64 HeldFile::size() const {
#ifdef Q_OS_WIN
    return static_cast<qint64>((quint64(impl_->info.nFileSizeHigh)<<32)|impl_->info.nFileSizeLow);
#else
    return impl_->info.st_size;
#endif
}
QString HeldFile::identity() const {
#ifdef Q_OS_WIN
    return QString("%1:%2:%3").arg(impl_->info.dwVolumeSerialNumber).arg(impl_->info.nFileIndexHigh).arg(impl_->info.nFileIndexLow);
#else
    return QString("%1:%2").arg(quint64(impl_->info.st_dev)).arg(quint64(impl_->info.st_ino));
#endif
}
void HeldFile::rewind() {
#ifdef Q_OS_WIN
    LARGE_INTEGER zero{};
    require(SetFilePointerEx(impl_->handle,zero,nullptr,FILE_BEGIN),ioError(QStringLiteral("Не удалось вернуться к началу файла")));
#else
    require(::lseek(impl_->fd,0,SEEK_SET)==0,ioError(QStringLiteral("Не удалось вернуться к началу файла")));
#endif
}
QByteArray HeldFile::read() {
    QByteArray bytes(64*1024,Qt::Uninitialized);
#ifdef Q_OS_WIN
    DWORD got=0;
    require(::ReadFile(impl_->handle,bytes.data(),static_cast<DWORD>(bytes.size()),&got,nullptr),ioError(QStringLiteral("Не удалось прочитать файл карантина")));
#else
    ssize_t got;
    do{got=::read(impl_->fd,bytes.data(),static_cast<size_t>(bytes.size()));}while(got<0 && errno==EINTR);
    require(got>=0,ioError(QStringLiteral("Не удалось прочитать файл карантина")));
#endif
    bytes.resize(static_cast<qsizetype>(got));
    return bytes;
}
bool HeldFile::unchanged() const {
#ifdef Q_OS_WIN
    BY_HANDLE_FILE_INFORMATION current{};
    return GetFileInformationByHandle(impl_->handle,&current) && impl_->same(current);
#else
    struct stat current{},named{};
    return ::fstat(impl_->fd,&current)==0 && impl_->same(current) &&
           ::fstatat(impl_->parent,impl_->name.constData(),&named,AT_SYMLINK_NOFOLLOW)==0 && S_ISREG(named.st_mode) && impl_->same(named);
#endif
}

void HeldFile::removeVerified(const QString &stagePath,const QString &expectedHash) {
    require(unchanged(),QStringLiteral("Файл изменён перед удалением исходного имени"));
#ifdef Q_OS_WIN
    Q_UNUSED(stagePath);
    Q_UNUSED(expectedHash);
    require(singleDataStream(impl_->handle),QStringLiteral("Перед удалением обнаружены дополнительные потоки файла"));
    FILE_DISPOSITION_INFO disposition{TRUE};
    require(SetFileInformationByHandle(impl_->handle,FileDispositionInfo,&disposition,sizeof(disposition)),ioError(QStringLiteral("Не удалось убрать проверенный файл по открытому дескриптору")));
#else
    const auto stage=QFile::encodeName(QFileInfo(stagePath).fileName());
    require(::mkdirat(impl_->parent,stage.constData(),0700)==0,ioError(QStringLiteral("Не удалось создать приватный промежуточный каталог")));
    const int stageFd=::openat(impl_->parent,stage.constData(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    require(stageFd>=0,ioError(QStringLiteral("Не удалось открыть промежуточный каталог")));
    auto closeStage=qScopeGuard([&]{::close(stageFd);});
    require(renameNew(impl_->parent,impl_->name.constData(),stageFd,"held")==0,ioError(QStringLiteral("Не удалось переместить имя в промежуточный каталог")));
    ::fsync(impl_->parent);
    ::fsync(stageFd);
    struct stat staged{},current{};
    bool good=::fstatat(stageFd,"held",&staged,AT_SYMLINK_NOFOLLOW)==0 && S_ISREG(staged.st_mode) && impl_->same(staged) &&
              ::fstat(impl_->fd,&current)==0 && impl_->same(current);
    if(good) {
        rewind();
        QCryptographicHash hash(QCryptographicHash::Sha256);
        for(auto bytes=read();!bytes.isEmpty();bytes=read())hash.addData(bytes);
        good=QString::fromLatin1(hash.result().toHex())==expectedHash;
    }
    if(!good) {
        const bool returned=renameNew(stageFd,"held",impl_->parent,impl_->name.constData())==0;
        if(returned)::unlinkat(impl_->parent,stage.constData(),AT_REMOVEDIR);
        throw Error(returned?QStringLiteral("Файл подменён. Исходное имя возвращено без удаления"):
                    QStringLiteral("Файл подменён. Сохранён в промежуточном каталоге: ")+stagePath);
    }
    require(::unlinkat(stageFd,"held",0)==0,ioError(QStringLiteral("Не удалось удалить проверенную промежуточную запись")));
    require(::fsync(stageFd)==0 && ::fsync(impl_->parent)==0,ioError(QStringLiteral("Не удалось подтвердить удаление исходного имени")));
    require(::unlinkat(impl_->parent,stage.constData(),AT_REMOVEDIR)==0,ioError(QStringLiteral("Не удалось убрать пустой промежуточный каталог")));
#endif
}
}
