#include "settings.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>

namespace resheto::service {
Settings loadSettings(const QString &path) {
    QFile file(path);
    constexpr qint64 maxBytes=64*1024;
    if(!QFileInfo(file).isFile() || !file.open(QIODevice::ReadOnly))
        throw Error(QStringLiteral("Не удалось открыть настройки службы: ")+path);
    const auto bytes=file.read(maxBytes+1);
    if(bytes.size()>maxBytes || file.error()!=QFileDevice::NoError)
        throw Error(QStringLiteral("Настройки службы превышают 64 КиБ или не читаются"));
    QJsonParseError parseError;
    const auto document=QJsonDocument::fromJson(bytes,&parseError);
    if(parseError.error!=QJsonParseError::NoError || !document.isObject())
        throw Error(QStringLiteral("Некорректный JSON настроек службы"));
    const auto object=document.object();
    const QStringList keys{"endpoint","db","heuristics","storage","network_rules"};
    for(auto it=object.begin();it!=object.end();++it) {
        if(!keys.contains(it.key()) || !it.value().isString() ||
           it.value().toString().contains(QChar(u'\0')) || it.value().toString().size()>4096)
            throw Error(QStringLiteral("Некорректное поле настроек службы: ")+it.key());
    }
    const QDir directory(QFileInfo(file).absolutePath());
    const auto configPath=[&](const char *key) {
        const auto value=object[key].toString();
        return value.isEmpty()?QString():QDir::cleanPath(directory.absoluteFilePath(value));
    };
    Settings settings;
    settings.endpoint=object["endpoint"].toString();
    settings.scan.signaturePath=configPath("db");
    settings.scan.heuristicPath=configPath("heuristics");
    settings.scan.storagePath=configPath("storage");
    settings.networkRulesPath=configPath("network_rules");
    return settings;
}
}
