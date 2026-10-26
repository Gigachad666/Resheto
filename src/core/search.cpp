#include "search.h"
#include <algorithm>
#include <cstring>
#include <queue>
namespace resheto {
SearchIndex::SearchIndex(const std::vector<Signature> &entries) : anchors_(entries.size()),lengths_(entries.size()) {
    nodes_.emplace_back();
    for(size_t i=0;i<entries.size();++i) {
        const auto &s=entries[i];
        if(s.kind=="HASH") { hashes_[s.value].push_back(i); continue; }
        if(s.offset) { fixed_.push_back(i); continue; }
        qsizetype bestStart=0,bestLength=0,start=0;
        for(qsizetype k=0;k<=s.value.size();++k) {
            if(k<s.value.size() && (s.mask.isEmpty() || s.mask[k]=='1')) continue;
            if(k-start>=bestLength) { bestStart=start; bestLength=k-start; }
            start=k+1;
        }
        // Последние 16 байт самой длинной значимой серии устраняют длинные почти совпадения.
        const auto len=qMin<qsizetype>(16,bestLength), anchor=bestStart+bestLength-len;
        anchors_[i]=anchor; lengths_[i]=len; int node=0;
        for(qsizetype k=anchor;k<anchor+len;++k) {
            auto c=static_cast<unsigned char>(s.value[k]); int next=nodes_[node].next[c];
            if(next<0) { next=static_cast<int>(nodes_.size()); nodes_[node].next[c]=next; nodes_.emplace_back(); }
            node=next;
        }
        nodes_[node].entries.push_back(i);
    }
    std::queue<int> queue;
    for(int c=0;c<256;++c) { auto &n=nodes_[0].next[c]; if(n<0) n=0; else queue.push(n); }
    while(!queue.empty()) {
        const int n=queue.front(); queue.pop(); const int f=nodes_[n].fail;
        nodes_[n].output=nodes_[f].entries.empty()?nodes_[f].output:f;
        for(int c=0;c<256;++c) {
            const int child=nodes_[n].next[c];
            if(child<0) nodes_[n].next[c]=nodes_[f].next[c];
            else { nodes_[child].fail=nodes_[f].next[c]; queue.push(child); }
        }
    }
}
static bool sizeFits(const Signature &s,qint64 size) { return (!s.minSize || size>=*s.minSize) && (!s.maxSize || size<=*s.maxSize); }
const Signature *SearchIndex::digest(const Snapshot &snap,const QByteArray &hash,qint64 size) const {
    const auto it=hashes_.constFind(hash); if(it==hashes_.cend()) return nullptr;
    for(auto i:it.value()) if(sizeFits(snap.entries[i],size)) return &snap.entries[i];
    return nullptr;
}
bool SearchIndex::patterns(const Snapshot &snap,const QByteArray &w,qint64 base,qint64 firstEnd,qint64 size,
                          const std::function<bool()> &cancel,const Signature *&found,qint64 &offset) const {
    quint64 work=0;
    auto verify=[&](size_t i,qint64 pos) {
        const auto &s=snap.entries[i]; const auto len=s.value.size();
        if(pos<0 || pos>w.size()-len || base+pos+len<=firstEnd || !sizeFits(s,size)) return true;
        if(found && (base+pos>offset || (base+pos==offset && s.id.toUtf8()>=found->id.toUtf8()))) return true;
        for(qsizetype k=0;k<len;) {
            if((++work & 1023)==0 && cancel()) return false;
            if(!s.mask.isEmpty() && s.mask[k]=='0') { ++k; continue; }
            qsizetype end=k+1;
            while(end<len && end-k<1024 && (s.mask.isEmpty() || s.mask[end]=='1')) ++end;
            if(std::memcmp(w.constData()+pos+k,s.value.constData()+k,static_cast<size_t>(end-k))!=0) return true;
            k=end;
        }
        found=&s; offset=base+pos; return true;
    };
    for(auto i:fixed_) { if(cancel()) return false; if(!verify(i,*snap.entries[i].offset-base)) return false; }
    int node=0;
    for(qsizetype k=0;k<w.size();++k) {
        if((k & 1023)==0 && cancel()) return false;
        node=nodes_[node].next[static_cast<unsigned char>(w[k])];
        for(int out=node;out>=0;out=nodes_[out].output) for(auto i:nodes_[out].entries) {
            if((++work & 1023)==0 && cancel()) return false;
            if(!verify(i,k-lengths_[i]+1-anchors_[i])) return false;
        }
    }
    return !cancel();
}
}
