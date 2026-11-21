#include "protocol.h"
#include <QJsonDocument>
#include <QRegularExpression>
#include <QtEndian>

namespace resheto::service::protocol {
namespace {
void require(bool valid,const QString &message) {
    if(!valid)throw Error(message);
}
int integer(const QJsonValue &value,int min,int max) {
    const auto number=value.toInt(-1);
    require(value.isDouble() && value.toDouble()==number && number>=min && number<=max,
            QStringLiteral("Недопустимый параметр страницы результатов"));
    return number;
}
QString queryText(const QJsonValue &value) {
    const auto string=value.toString();
    require(value.isString() && string.size()<=4096 && !string.contains(QChar(u'\0')),
            QStringLiteral("Некорректный текст поиска"));
    return string;
}
}

bool validEndpoint(const QString &name) {
    static const QRegularExpression pattern(QStringLiteral("\\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\\z"));
    return pattern.match(name).hasMatch();
}

QByteArray frame(const QJsonObject &message,qsizetype limit) {
    const auto body=QJsonDocument(message).toJson(QJsonDocument::Compact);
    require(body.size()<=limit,QStringLiteral("Ответ службы слишком велик. Уменьшите размер страницы"));
    QByteArray bytes(headerSize,0);
    qToBigEndian<quint32>(static_cast<quint32>(body.size()),bytes.data());
    bytes+=body;
    return bytes;
}

std::optional<QJsonObject> readFrame(const QByteArray &bytes,qsizetype limit) {
    if(bytes.size()<headerSize)return {};
    const auto size=static_cast<qsizetype>(qFromBigEndian<quint32>(bytes.constData()));
    require(size>0 && size<=limit,QStringLiteral("Недопустимый размер локального сообщения"));
    if(bytes.size()<headerSize+size)return {};
    require(bytes.size()==headerSize+size,QStringLiteral("Ожидается один локальный запрос на соединение"));
    QJsonParseError error;
    const auto document=QJsonDocument::fromJson(bytes.mid(headerSize),&error);
    require(error.error==QJsonParseError::NoError && document.isObject(),QStringLiteral("Ожидался объект JSON"));
    return document.object();
}

qint64 counter(const QJsonValue &value) {
    const auto string=value.toString();
    bool valid=false;
    const auto number=string.toLongLong(&valid);
    require(value.isString() && valid && number>=0 && QString::number(number)==string,
            QStringLiteral("Ожидалось неотрицательное целое в десятичной строке"));
    return number;
}

QJsonObject encodeQuery(const ResultQuery &query) {
    return {{"filter",static_cast<int>(query.filter)},{"sort",static_cast<int>(query.sort)},
            {"object",static_cast<int>(query.object)},{"descending",query.descending},
            {"offset",QString::number(query.offset)},{"upper_row",QString::number(query.upperRow)},
            {"limit",query.limit},{"path",query.path},{"text",query.text}};
}

ResultQuery decodeQuery(const QJsonObject &object) {
    require(object.size()==9 && object["descending"].isBool(),QStringLiteral("Некорректные параметры страницы"));
    ResultQuery query;
    query.filter=static_cast<ResultFilter>(integer(object["filter"],0,static_cast<int>(ResultFilter::NotChecked)));
    query.sort=static_cast<ResultSort>(integer(object["sort"],0,static_cast<int>(ResultSort::Signature)));
    query.object=static_cast<ResultObject>(integer(object["object"],0,static_cast<int>(ResultObject::Processes)));
    query.descending=object["descending"].toBool();
    query.offset=counter(object["offset"]);
    query.upperRow=counter(object["upper_row"]);
    query.limit=integer(object["limit"],1,pageLimit);
    query.path=queryText(object["path"]);
    query.text=queryText(object["text"]);
    return query;
}
}
