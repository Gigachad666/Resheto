#pragma once
#include <QByteArray>
#include <QtEndian>
namespace resheto::fixtures {
// Безвредные структурные данные, не предназначенные для исполнения.
inline QByteArray pe(bool writable) {
    QByteArray b(1024,0); auto n16=[&](int p,quint16 n){qToLittleEndian(n,b.data()+p);}; auto n32=[&](int p,quint32 n){qToLittleEndian(n,b.data()+p);}; auto n64=[&](int p,quint64 n){qToLittleEndian(n,b.data()+p);};
    b.replace(0,2,"MZ"); n32(60,128); b.replace(128,4,QByteArray("PE\0\0",4)); n16(132,0x8664); n16(134,1); n16(148,240); n16(150,0x22);
    n16(152,0x20b); n32(168,0x1000); n64(176,0x140000000); n32(184,0x1000); n32(188,0x200); n32(208,0x2000); n32(212,512); n32(260,16);
    b.replace(392,5,".text"); n32(400,512); n32(404,0x1000); n32(408,512); n32(412,512); n32(428,writable?0xe0000020:0x60000020); return b;
}
inline QByteArray elf(bool writable) {
    QByteArray b(512,0); auto n16=[&](int p,quint16 n){qToLittleEndian(n,b.data()+p);}; auto n32=[&](int p,quint32 n){qToLittleEndian(n,b.data()+p);}; auto n64=[&](int p,quint64 n){qToLittleEndian(n,b.data()+p);};
    b.replace(0,4,QByteArray("\x7f" "ELF",4)); b[4]=2; b[5]=1; b[6]=1; n16(16,2); n16(18,62); n32(20,1); n64(24,0x400080); n64(32,64);
    n16(52,64); n16(54,56); n16(56,1); n32(64,1); n32(68,writable?7:5); n64(80,0x400000); n64(88,0x400000); n64(96,512); n64(104,512); n64(112,4096); return b;
}
}
