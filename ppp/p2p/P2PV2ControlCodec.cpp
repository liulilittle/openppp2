#include <ppp/p2p/P2PV2Codec.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <limits>

namespace ppp::p2p {
namespace {
bool Valid(const P2PV2ControlPacket& p) noexcept {
    return P2PV2ControlWireSize(p.type)!=0 && p.sender_role<=1 && p.receiver_role<=1 &&
        p.sender_role!=p.receiver_role && p.direction==p.sender_role && p.setup_ttl_seconds==10 &&
        p.sequence!=std::numeric_limits<std::uint32_t>::max() &&
        p.offer_hash!=P2POfferHash{} && p.connection_epoch!=P2PId{} &&
        IsCanonicalP2PCandidate(p.source) && IsCanonicalP2PCandidate(p.destination);
}
void Endpoint(std::uint8_t* b,const P2PCandidateEndpoint& e) noexcept {
    b[0]=e.address_family; std::copy(e.address.begin(),e.address.end(),b+1);
    b[17]=static_cast<std::uint8_t>(e.port>>8); b[18]=static_cast<std::uint8_t>(e.port);
}
bool Tag(const P2PV2ControlPacket& packet,const P2PExporterKey& key,
    const P2POfferHash* binding,std::array<std::uint8_t,16>& output) noexcept {
    auto copy=packet; copy.token={}; std::vector<std::uint8_t> bytes;
    if (!SerializeP2PV2Control(copy,bytes)) return false;
    try { if (binding) bytes.insert(bytes.end(),binding->begin(),binding->end()); }
    catch (...) { return false; }
    std::array<std::uint8_t,32> full{}; unsigned size=0;
    const bool ok=HMAC(EVP_sha256(),key.data(),key.size(),bytes.data(),bytes.size(),full.data(),&size)!=nullptr && size==32;
    if (ok) std::copy(full.begin(),full.begin()+16,output.begin());
    OPENSSL_cleanse(full.data(),full.size()); return ok;
}
}
std::size_t P2PV2ControlWireSize(P2PV2ControlType type) noexcept {
    switch(type) {
    case P2PV2ControlType::Probe: case P2PV2ControlType::ProbeAck: return 158;
    case P2PV2ControlType::KeyCommit: case P2PV2ControlType::KeyCommitAck: return 190;
    case P2PV2ControlType::MigrateChallenge: case P2PV2ControlType::MigrateAck: return 126;
    default: return 0;
    }
}
bool SerializeP2PV2Control(const P2PV2ControlPacket& p,std::vector<std::uint8_t>& out) noexcept {
    if (!Valid(p)) return false;
    try {
        std::vector<std::uint8_t> b(P2PV2ControlWireSize(p.type),0);
        b[0]=2; b[1]=static_cast<std::uint8_t>(p.type);
        std::copy(p.offer_hash.begin(),p.offer_hash.end(),b.begin()+4);
        b[36]=p.sender_role; b[37]=p.receiver_role; b[38]=p.direction;
        std::copy(p.connection_epoch.begin(),p.connection_epoch.end(),b.begin()+39);
        Endpoint(b.data()+55,p.source); Endpoint(b.data()+74,p.destination);
        for(unsigned n=0;n<4;++n) b[93+n]=static_cast<std::uint8_t>(p.sequence>>((3-n)*8));
        std::copy(p.nonce.begin(),p.nonce.end(),b.begin()+97); b[109]=p.setup_ttl_seconds;
        std::copy(p.token.begin(),p.token.end(),b.begin()+110);
        if (p.type==P2PV2ControlType::ProbeAck)
            std::copy(p.probe_transcript_hash.begin(),p.probe_transcript_hash.end(),b.begin()+126);
        if (p.type==P2PV2ControlType::KeyCommit) {
            std::copy(p.previous_offer_hash.begin(),p.previous_offer_hash.end(),b.begin()+126);
            std::copy(p.probe_transcript_hash.begin(),p.probe_transcript_hash.end(),b.begin()+158);
        }
        if (p.type==P2PV2ControlType::KeyCommitAck) {
            std::copy(p.commit_transcript_hash.begin(),p.commit_transcript_hash.end(),b.begin()+126);
            std::copy(p.probe_transcript_hash.begin(),p.probe_transcript_hash.end(),b.begin()+158);
        }
        out.swap(b); return true;
    } catch (...) { return false; }
}
bool ParseP2PV2Control(const std::vector<std::uint8_t>& b,P2PV2ControlPacket& out) noexcept {
    if (b.size()<126 || b[0]!=2 || b[2]!=0 || b[3]!=0) return false;
    const auto type=static_cast<P2PV2ControlType>(b[1]);
    if (b.size()!=P2PV2ControlWireSize(type)) return false;
    P2PV2ControlPacket p; p.type=type;
    std::copy(b.begin()+4,b.begin()+36,p.offer_hash.begin());
    p.sender_role=b[36]; p.receiver_role=b[37]; p.direction=b[38];
    std::copy(b.begin()+39,b.begin()+55,p.connection_epoch.begin());
    if (!detail::ParseCandidate(b,55,p.source) || !detail::ParseCandidate(b,74,p.destination)) return false;
    p.sequence=0; for(unsigned n=0;n<4;++n) p.sequence=(p.sequence<<8)|b[93+n];
    std::copy(b.begin()+97,b.begin()+109,p.nonce.begin()); p.setup_ttl_seconds=b[109];
    std::copy(b.begin()+110,b.begin()+126,p.token.begin());
    if (type==P2PV2ControlType::Probe &&
        !std::all_of(b.begin()+126,b.end(),[](auto x) { return x==0; })) return false;
    if (type==P2PV2ControlType::ProbeAck)
        std::copy(b.begin()+126,b.end(),p.probe_transcript_hash.begin());
    if (type==P2PV2ControlType::KeyCommit) {
        std::copy(b.begin()+126,b.begin()+158,p.previous_offer_hash.begin());
        std::copy(b.begin()+158,b.end(),p.probe_transcript_hash.begin());
    }
    if (type==P2PV2ControlType::KeyCommitAck) {
        std::copy(b.begin()+126,b.begin()+158,p.commit_transcript_hash.begin());
        std::copy(b.begin()+158,b.end(),p.probe_transcript_hash.begin());
    }
    if (!Valid(p)) return false; out=p; return true;
}
bool SignP2PV2Control(P2PV2ControlPacket& p,const P2PExporterKey& key,const P2POfferHash* binding) noexcept {
    std::array<std::uint8_t,16> token{}; if (!Tag(p,key,binding,token)) return false;
    p.token=token; return true;
}
bool VerifyP2PV2Control(const P2PV2ControlPacket& p,const P2PExporterKey& key,const P2POfferHash* binding) noexcept {
    std::array<std::uint8_t,16> token{};
    return Tag(p,key,binding,token) && CRYPTO_memcmp(token.data(),p.token.data(),token.size())==0;
}
bool HashP2PV2Control(const P2PV2ControlPacket& p,P2POfferHash& out) noexcept {
    std::vector<std::uint8_t> bytes; P2POfferHash hash{}; unsigned length=0;
    if (!SerializeP2PV2Control(p,bytes) || EVP_Digest(bytes.data(),bytes.size(),hash.data(),&length,EVP_sha256(),nullptr)!=1 || length!=32) return false;
    out=hash; return true;
}
}
