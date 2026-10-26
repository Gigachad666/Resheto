#pragma once
#include "model.h"
#include <QHash>
#include <array>
namespace resheto {
// Структуры строятся один раз; содержат индексы, а не указатели на перемещаемые записи.
class SearchIndex {
    struct Node { std::array<int,256> next; int fail=0, output=-1; std::vector<size_t> entries; Node() { next.fill(-1); } };
    std::vector<Node> nodes_;
    std::vector<qsizetype> anchors_, lengths_;
    std::vector<size_t> fixed_;
    QHash<QByteArray,std::vector<size_t>> hashes_;
public:
    explicit SearchIndex(const std::vector<Signature> &entries);
    const Signature *digest(const Snapshot &snapshot,const QByteArray &hash,qint64 size) const;
    // false означает отмену. Выбор: минимальное абсолютное смещение, затем id BINARY.
    bool patterns(const Snapshot &,const QByteArray &,qint64 base,qint64 firstEnd,qint64 size,
                  const std::function<bool()> &,const Signature *&found,qint64 &offset) const;
};
}
