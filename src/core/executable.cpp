#include "executable.h"
#include <QFileInfo>
#include <QStringList>
#include <QtEndian>
#include <limits>

namespace resheto {
namespace {
quint16 u16(const QByteArray &b,qsizetype at) { return qFromLittleEndian<quint16>(b.constData()+at); }
quint32 u32(const QByteArray &b,qsizetype at) { return qFromLittleEndian<quint32>(b.constData()+at); }
quint64 u64(const QByteArray &b,qsizetype at) { return qFromLittleEndian<quint64>(b.constData()+at); }
bool fits(quint64 at,quint64 count,quint64 size) { return at<=size && count<=size-at; }
void require(bool ok,const char *reason) { if(!ok) throw Error(QString::fromUtf8(reason)); }
}
ExecutableFeatures executableFeatures(ReadFile &file,const QString &path,const std::function<bool()> &cancel) {
    ExecutableFeatures out;
    const quint64 size=static_cast<quint64>(file.size());
    const auto suffix=QFileInfo(path).suffix().toLower();
    auto read=[&](quint64 at,quint64 count) {
        if(cancel()) throw Error(QStringLiteral("Извлечение признаков отменено"));
        require(fits(at,count,size) && count<=65536,"Структура исполняемого файла выходит за границы");
        return file.readAt(static_cast<qint64>(at),static_cast<qsizetype>(count));
    };
    try {
        const auto head=read(0,qMin<quint64>(64,size));
        bool wx=false,entryExecutable=false,noEntry=false;
        if(head.startsWith("MZ")) {
            out.format="PE";
            require(head.size()==64,"Обрезан DOS-заголовок PE");
            const quint64 pe=u32(head,60);
            const auto coff=read(pe,24);
            require(coff.left(4)==QByteArray("PE\0\0",4),"Отсутствует заголовок PE");
            if(u16(coff,4)!=0x8664) { out.code="unsupported_arch"; out.reason=QStringLiteral("Поддерживается PE x86-64"); return out; }
            const quint64 sections=u16(coff,6), optionalSize=u16(coff,20);
            require(sections>=1 && sections<=96 && optionalSize>=112 && optionalSize<=4096,"Недопустимые размеры заголовков PE");
            const auto optional=read(pe+24,optionalSize);
            if(u16(optional,0)!=0x20b) { out.code="unsupported_format"; out.reason=QStringLiteral("Поддерживается PE32+"); return out; }
            out.supported=true;
            const quint64 entry=u32(optional,16);
            // У DLL/драйверов и образов без начальной функции нулевая точка допустима.
            noEntry=entry==0;
            const auto table=read(pe+24+optionalSize,sections*40);
            for(quint64 i=0;i<sections;++i) {
                if(cancel()) throw Error(QStringLiteral("Извлечение признаков отменено"));
                const qsizetype p=static_cast<qsizetype>(i*40);
                const quint64 virtualSize=u32(table,p+8), address=u32(table,p+12);
                const quint64 rawSize=u32(table,p+16), rawOffset=u32(table,p+20);
                const quint32 flags=u32(table,p+36);
                require(fits(rawOffset,rawSize,size),"Секция PE выходит за границы файла");
                const quint64 mapped=qMax(virtualSize,rawSize);
                require(fits(address,mapped,quint64(1)<<32),"Переполнение виртуального диапазона PE");
                const bool executable=(flags & 0x20000000u)!=0, writable=(flags & 0x80000000u)!=0;
                wx|=mapped>0 && executable && writable;
                entryExecutable|=executable && entry>=address && entry-address<mapped;
            }
            out.values["extension_mismatch"]=!QStringList{"exe","dll","sys","scr","ocx","cpl"}.contains(suffix);
        } else if(head.startsWith(QByteArray("\x7f" "ELF",4))) {
            out.format="ELF";
            require(head.size()==64,"Обрезан ELF-заголовок");
            if(static_cast<unsigned char>(head[4])!=2 || static_cast<unsigned char>(head[5])!=1 || u16(head,18)!=62) {
                out.code="unsupported_arch"; out.reason=QStringLiteral("Поддерживается ELF64 little-endian x86-64"); return out;
            }
            require(static_cast<unsigned char>(head[6])==1 && u32(head,20)==1 && u16(head,52)==64,"Недопустимый ELF-заголовок");
            const auto type=u16(head,16);
            if(type!=2 && type!=3) { out.code="unsupported_format"; out.reason=QStringLiteral("Поддерживаются ELF executable/shared object"); return out; }
            out.supported=true;
            const quint64 entry=u64(head,24), tableOffset=u64(head,32), count=u16(head,56), step=u16(head,54);
            require(count>=1 && count<=1024 && step==56,"Неподдерживаемая таблица сегментов ELF");
            const auto table=read(tableOffset,count*step); noEntry=entry==0;
            for(quint64 i=0;i<count;++i) {
                if(cancel()) throw Error(QStringLiteral("Извлечение признаков отменено"));
                const qsizetype p=static_cast<qsizetype>(i*step);
                if(u32(table,p)!=1) continue; // PT_LOAD
                const quint32 flags=u32(table,p+4);
                const quint64 offset=u64(table,p+8), address=u64(table,p+16), disk=u64(table,p+32), memory=u64(table,p+40);
                require(disk<=memory && fits(offset,disk,size) && memory<=std::numeric_limits<quint64>::max()-address,"Некорректные границы сегмента ELF");
                const bool executable=(flags & 1)!=0, writable=(flags & 2)!=0;
                wx|=memory>0 && executable && writable;
                entryExecutable|=executable && entry>=address && entry-address<memory;
            }
            out.values["extension_mismatch"]=!suffix.isEmpty() && suffix!="elf" && suffix!="so" && !QFileInfo(path).fileName().contains(".so.");
        } else {
            out.code="unsupported_format"; out.reason=QStringLiteral("Объект не является поддерживаемым PE/ELF"); return out;
        }
        out.values["writable_executable"]=wx;
        out.values["entry_outside_executable"]=!noEntry && !entryExecutable;
        out.complete=true;
    } catch(const Error &e) {
        out.values={}; out.code=cancel() ? "cancelled" : "executable_structure"; out.reason=e.message;
        // Узнанный, но обрезанный формат — неполный разбор, а не отрицательные признаки.
        out.supported=!out.format.isEmpty();
    }
    return out;
}
}
