#include <ppp/p2p/P2PRelayOfferV2.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>

namespace ppp::p2p {
namespace {

template<class T> bool Zero(const T& v) noexcept {
    return std::all_of(v.begin(), v.end(), [](auto b) { return b == 0; });
}
template<class T> void Clean(T& v) noexcept { OPENSSL_cleanse(&v, sizeof(v)); }
bool Valid(const P2PRelayOfferV2& o) noexcept {
    return o.version == 2 && o.setup_ttl_seconds == 10 &&
        o.key_lifetime_seconds == 60 && o.refresh_after_seconds == 40 &&
        o.previous_receive_grace_ms == 5000 && o.cipher == 1 &&
        o.key_generation != 0 && o.initiator_candidate_revision != 0 &&
        o.responder_candidate_revision != 0 && !Zero(o.offer_id) &&
        !Zero(o.connection_epoch) && !Zero(o.initiator_session_id) &&
        !Zero(o.responder_session_id) && !Zero(o.initiator_peer_id) &&
        !Zero(o.responder_peer_id) && !Zero(o.candidate_set_hash) &&
        o.initiator_session_id != o.responder_session_id &&
        o.initiator_peer_id < o.responder_peer_id;
}
template<std::size_t N> void Put(std::uint8_t*& p,
    const std::array<std::uint8_t,N>& a) noexcept {
    std::memcpy(p,a.data(),N); p += N;
}
void Number(std::uint8_t*& p, std::uint64_t n, unsigned width) noexcept {
    for (unsigned i=width; i>0; --i) *p++ = static_cast<std::uint8_t>(n >> ((i-1)*8));
}
template<std::size_t N> void Get(const std::uint8_t*& p,
    std::array<std::uint8_t,N>& a) noexcept {
    std::memcpy(a.data(),p,N); p += N;
}
std::uint64_t ReadNumber(const std::uint8_t*& p, unsigned width) noexcept {
    std::uint64_t n=0; while(width--) n=(n<<8)|*p++; return n;
}
bool Digest(const void* data, std::size_t size, P2POfferHash& out) noexcept {
    P2POfferHash hash{}; unsigned length=0;
    if (EVP_Digest(data,size,hash.data(),&length,EVP_sha256(),nullptr)!=1 || length!=32) return false;
    out=hash; return true;
}
bool Kdf(const P2PExporterKey& key, const P2POfferHash& salt,
    const std::uint8_t* info, std::size_t info_size,
    std::uint8_t* output, std::size_t size) noexcept {
    auto* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,nullptr);
    if (!ctx) return false;
    std::size_t length=size;
    const bool ok=EVP_PKEY_derive_init(ctx)>0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx,EVP_sha256())>0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx,salt.data(),salt.size())>0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx,key.data(),key.size())>0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx,info,info_size)>0 &&
        EVP_PKEY_derive(ctx,output,&length)>0 && length==size;
    EVP_PKEY_CTX_free(ctx); return ok;
}
bool WrapKey(const P2PExporterKey& exporter, const P2POfferHash& hash,
    P2PPeerRole role, P2PWrapKey& output) noexcept {
    if (Zero(exporter)) return false;
    static constexpr char label[]="openppp2 p2p v2 wrap key";
    std::array<std::uint8_t,sizeof(label)> info{};
    std::memcpy(info.data(),label,sizeof(label)-1);
    info.back()=static_cast<std::uint8_t>(role);
    return Kdf(exporter,hash,info.data(),info.size(),output.data(),output.size());
}
P2PRelayOfferV2 Make(const P2PRelayOfferV2Input& i,
    const P2PRelayOfferSecrets& s) noexcept {
    P2PRelayOfferV2 o;
    o.offer_id=s.offer_id; o.connection_epoch=s.connection_epoch;
    o.initiator_session_id=i.initiator_session_id; o.responder_session_id=i.responder_session_id;
    o.initiator_peer_id=i.initiator_peer_id; o.responder_peer_id=i.responder_peer_id;
    o.key_generation=i.key_generation; o.previous_offer_hash=i.previous_offer_hash;
    o.initiator_candidate_revision=i.initiator_candidate_revision;
    o.responder_candidate_revision=i.responder_candidate_revision;
    o.candidate_set_hash=i.candidate_set_hash; return o;
}
bool RandomSecrets(P2PRelayOfferSecrets& s) noexcept {
    return RAND_bytes(s.offer_id.data(),16)==1 && RAND_bytes(s.connection_epoch.data(),16)==1 &&
        RAND_bytes(s.pair_seed.data(),32)==1 && RAND_bytes(s.initiator_wrap_nonce.data(),12)==1 &&
        RAND_bytes(s.responder_wrap_nonce.data(),12)==1;
}
bool Export(const P2PSessionExporter& fn, const P2PExporterContextV2& context,
    P2PExporterKey& key) noexcept {
    if (!fn) return false;
    try { return fn(P2PWrapExporterLabelV2,context.data(),context.size(),key.data(),key.size()); }
    catch (...) { return false; }
}
int Hex(char c) noexcept {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    if (c>='A' && c<='F') return c-'A'+10;
    return -1;
}

class Async final : public std::enable_shared_from_this<Async> {
public:
    P2PRelayOfferV2Input input;
    P2PAsyncSessionExporterV2 first, second;
    P2PRelayOfferV2Completion completion;
    P2PRelayOfferSecrets secrets;
    P2PExporterContextV2 contexts[2]{};
    P2PExporterKey keys[2]{};
    std::atomic<int> stage{0};
    ~Async() { Clean(secrets); Clean(keys); }
    void Finish(bool ok, const P2PRelayOfferV2Bundle& bundle={}) noexcept {
        if (stage.exchange(3)==3) return;
        auto cb=std::move(completion); first={}; second={}; Clean(secrets); Clean(keys);
        if (cb) { try { cb(ok,bundle); } catch (...) {} }
    }
    void OnSecond(bool ok) noexcept {
        int expected=1; if (!stage.compare_exchange_strong(expected,2)) return;
        P2PRelayOfferV2Bundle bundle;
        Finish(ok && BuildP2PRelayOfferV2Bundle(input,keys[0],keys[1],secrets,bundle),bundle);
    }
    void OnFirst(bool ok) noexcept {
        int expected=0; if (!stage.compare_exchange_strong(expected,1)) return;
        if (!ok) { Finish(false); return; }
        auto self=shared_from_this(); auto exporter=second;
        try { exporter(P2PWrapExporterLabelV2,contexts[1],keys[1],
            [self](bool ready) { self->OnSecond(ready); }); }
        catch (...) { OnSecond(false); }
    }
    void Start() noexcept {
        auto offer=Make(input,secrets);
        if (!RandomSecrets(secrets)) { Finish(false); return; }
        offer=Make(input,secrets);
        if (!BuildP2PExporterContextV2(offer,P2PPeerRole::Initiator,contexts[0]) ||
            !BuildP2PExporterContextV2(offer,P2PPeerRole::Responder,contexts[1])) {
            Finish(false); return;
        }
        auto self=shared_from_this(); auto exporter=first;
        try { exporter(P2PWrapExporterLabelV2,contexts[0],keys[0],
            [self](bool ready) { self->OnFirst(ready); }); }
        catch (...) { OnFirst(false); }
    }
};
}

bool SerializeP2PRelayOfferV2(const P2PRelayOfferV2& o, P2PRelayOfferV2Bytes& out) noexcept {
    if (!Valid(o)) return false;
    P2PRelayOfferV2Bytes b{}; auto* p=b.data(); *p++=2;
    Put(p,o.offer_id); Put(p,o.initiator_session_id); Put(p,o.responder_session_id);
    Put(p,o.initiator_peer_id); Put(p,o.responder_peer_id); Put(p,o.connection_epoch);
    Number(p,o.key_generation,8); Put(p,o.previous_offer_hash); *p++=o.setup_ttl_seconds;
    Number(p,o.key_lifetime_seconds,2); Number(p,o.refresh_after_seconds,2);
    Number(p,o.previous_receive_grace_ms,2); *p++=o.cipher;
    Number(p,o.initiator_candidate_revision,8); Number(p,o.responder_candidate_revision,8);
    Put(p,o.candidate_set_hash); if (p!=b.data()+b.size()) return false;
    out=b; return true;
}
bool HashP2PRelayOfferV2(const P2PRelayOfferV2& o,P2POfferHash& out) noexcept {
    P2PRelayOfferV2Bytes bytes{}; return SerializeP2PRelayOfferV2(o,bytes) && Digest(bytes.data(),bytes.size(),out);
}
bool BuildP2PExporterContextV2(const P2PRelayOfferV2& o,P2PPeerRole role,P2PExporterContextV2& out) noexcept {
    P2POfferHash hash{};
    if (static_cast<unsigned>(role)>1 || !HashP2PRelayOfferV2(o,hash)) return false;
    P2PExporterContextV2 b{}; auto* p=b.data();
    Put(p,role==P2PPeerRole::Initiator?o.initiator_session_id:o.responder_session_id);
    Put(p,o.initiator_peer_id); Put(p,o.responder_peer_id);
    Put(p,o.initiator_session_id); Put(p,o.responder_session_id);
    Put(p,o.connection_epoch); Put(p,o.offer_id); *p++=2; Put(p,hash);
    out=b; return true;
}
bool DeriveP2PV2KeyMaterial(const P2PPairSeed& seed,const P2POfferHash& hash,P2PV1KeyMaterial& out) noexcept {
    if (Zero(seed) || Zero(hash)) return false;
    P2PV1KeyMaterial keys{};
    const auto derive=[&](const char* label,auto& target) {
        return Kdf(seed,hash,reinterpret_cast<const std::uint8_t*>(label),std::strlen(label),target.data(),target.size());
    };
    const bool ok=derive("openppp2 p2p v2 initiator to responder key",keys.initiator_to_responder_key) &&
        derive("openppp2 p2p v2 responder to initiator key",keys.responder_to_initiator_key) &&
        derive("openppp2 p2p v2 initiator to responder nonce",keys.initiator_to_responder_nonce) &&
        derive("openppp2 p2p v2 responder to initiator nonce",keys.responder_to_initiator_nonce) &&
        derive("openppp2 p2p v2 offer token",keys.offer_token_key);
    if (ok) out=keys; Clean(keys); return ok;
}
bool HashP2PV2CandidateSet(const P2PId& si,const P2PId& sr,std::uint64_t ri,std::uint64_t rr,
    const std::vector<P2PCandidateEndpoint>& ci,const std::vector<P2PCandidateEndpoint>& cr,P2POfferHash& out) noexcept {
    if (Zero(si) || Zero(sr) || si==sr || !ri || !rr || ci.empty() || cr.empty() || ci.size()>2 || cr.size()>2) return false;
    std::array<std::uint8_t,128> bytes{}; auto* p=bytes.data();
    for (unsigned role=0; role<2; ++role) {
        const auto& input=role==0?ci:cr;
        std::array<std::array<std::uint8_t,19>,2> sorted{};
        for (std::size_t n=0; n<input.size(); ++n) {
            if ((input[n].address_family != 4 && input[n].address_family != 6) ||
                !IsCanonicalP2PCandidate(input[n])) return false;
            auto* target=sorted[n].data(); *target++=input[n].address_family;
            Put(target,input[n].address); Number(target,input[n].port,2);
        }
        std::sort(sorted.begin(),sorted.begin()+input.size());
        if (input.size()==2 && sorted[0]==sorted[1]) return false;
        *p++=static_cast<std::uint8_t>(role); Put(p,role==0?si:sr); Number(p,role==0?ri:rr,8);
        *p++=static_cast<std::uint8_t>(input.size());
        for (std::size_t n=0; n<input.size(); ++n) Put(p,sorted[n]);
    }
    return Digest(bytes.data(),p-bytes.data(),out);
}
bool BuildP2PRelayOfferV2Bundle(const P2PRelayOfferV2Input& i,const P2PExporterKey& ei,const P2PExporterKey& er,
    const P2PRelayOfferSecrets& s,P2PRelayOfferV2Bundle& out) noexcept {
    P2PRelayOfferV2Bundle bundle; bundle.offer=Make(i,s);
    P2POfferHash hash{}; P2PWrapKey ki{},kr{};
    const bool ok=!Zero(s.pair_seed) && HashP2PRelayOfferV2(bundle.offer,hash) &&
        WrapKey(ei,hash,P2PPeerRole::Initiator,ki) && WrapKey(er,hash,P2PPeerRole::Responder,kr) &&
        WrapP2PPairSeed(ki,hash,i.initiator_peer_id,P2PPeerRole::Initiator,s.initiator_wrap_nonce,s.pair_seed,bundle.initiator_envelope) &&
        WrapP2PPairSeed(kr,hash,i.responder_peer_id,P2PPeerRole::Responder,s.responder_wrap_nonce,s.pair_seed,bundle.responder_envelope);
    Clean(ki); Clean(kr); if (ok) out=bundle; return ok;
}
bool CreateP2PRelayOfferV2Bundle(const P2PRelayOfferV2Input& i,const P2PSessionExporter& ei,
    const P2PSessionExporter& er,P2PRelayOfferV2Bundle& out) noexcept {
    P2PRelayOfferSecrets secrets; P2PExporterKey ki{},kr{}; P2PExporterContextV2 ci{},cr{};
    const bool random=RandomSecrets(secrets); const auto offer=Make(i,secrets);
    const bool ok=random && BuildP2PExporterContextV2(offer,P2PPeerRole::Initiator,ci) &&
        BuildP2PExporterContextV2(offer,P2PPeerRole::Responder,cr) && Export(ei,ci,ki) && Export(er,cr,kr) &&
        BuildP2PRelayOfferV2Bundle(i,ki,kr,secrets,out);
    Clean(secrets); Clean(ki); Clean(kr); return ok;
}
bool CreateP2PRelayOfferV2BundleAsync(const P2PRelayOfferV2Input& i,const P2PAsyncSessionExporterV2& ei,
    const P2PAsyncSessionExporterV2& er,const P2PRelayOfferV2Completion& cb) noexcept {
    if (!ei || !er || !cb) return false;
    try { auto state=std::make_shared<Async>(); state->input=i; state->first=ei;
        state->second=er; state->completion=cb; state->Start(); return true; }
    catch (...) { return false; }
}
P2PAsyncSessionExporterV2 ScheduleP2PSessionExporterV2(const P2PTaskScheduler& schedule,
    const P2PSessionExporter& exporter) noexcept {
    try { return [schedule,exporter](const char* label,const P2PExporterContextV2& context,
        P2PExporterKey& output,const P2PExportCompletion& done) {
        const auto task=[exporter,label,context,&output,done] {
            bool ok=false; try { ok=exporter && exporter(label,context.data(),context.size(),output.data(),output.size()); }
            catch (...) {} if (done) done(ok);
        };
        if (!schedule || !schedule(task)) { if (done) done(false); }
    }; } catch (...) { return {}; }
}
bool EncodeP2PRelayOfferRecipientV2Hex(const P2PRelayOfferV2& o,const P2PWrappedPairSeed& e,std::string& out) noexcept {
    P2PRelayOfferV2Bytes common{};
    if (!SerializeP2PRelayOfferV2(o,common) || static_cast<unsigned>(e.recipient_role)>1 ||
        e.recipient_peer_id!=(e.recipient_role==P2PPeerRole::Initiator?o.initiator_peer_id:o.responder_peer_id)) return false;
    P2PRelayOfferRecipientV2Bytes bytes{}; auto* p=bytes.data(); Put(p,common); Put(p,e.recipient_peer_id);
    *p++=static_cast<std::uint8_t>(e.recipient_role); Put(p,e.wrap_nonce); Put(p,e.ciphertext); Put(p,e.auth_tag);
    try { std::string encoded(bytes.size()*2,'0'); const char* digits="0123456789abcdef";
        for (std::size_t n=0;n<bytes.size();++n) { encoded[2*n]=digits[bytes[n]>>4]; encoded[2*n+1]=digits[bytes[n]&15]; }
        out.swap(encoded); return true; } catch (...) { return false; }
}
bool ParseP2PRelayOfferRecipientV2Hex(const std::string& encoded,P2PRelayOfferV2& output,P2PWrappedPairSeed& envelope) noexcept {
    if (encoded.size()!=P2PRelayOfferRecipientV2Bytes{}.size()*2) return false;
    P2PRelayOfferRecipientV2Bytes bytes{};
    for (std::size_t n=0;n<bytes.size();++n) { const int a=Hex(encoded[2*n]),b=Hex(encoded[2*n+1]);
        if (a<0 || b<0) return false; bytes[n]=static_cast<std::uint8_t>((a<<4)|b); }
    auto* p=static_cast<const std::uint8_t*>(bytes.data()); P2PRelayOfferV2 o;
    o.version=*p++; Get(p,o.offer_id); Get(p,o.initiator_session_id); Get(p,o.responder_session_id);
    Get(p,o.initiator_peer_id); Get(p,o.responder_peer_id); Get(p,o.connection_epoch);
    o.key_generation=ReadNumber(p,8); Get(p,o.previous_offer_hash); o.setup_ttl_seconds=*p++;
    o.key_lifetime_seconds=static_cast<std::uint16_t>(ReadNumber(p,2));
    o.refresh_after_seconds=static_cast<std::uint16_t>(ReadNumber(p,2));
    o.previous_receive_grace_ms=static_cast<std::uint16_t>(ReadNumber(p,2)); o.cipher=*p++;
    o.initiator_candidate_revision=ReadNumber(p,8); o.responder_candidate_revision=ReadNumber(p,8); Get(p,o.candidate_set_hash);
    P2PWrappedPairSeed e; Get(p,e.recipient_peer_id); e.recipient_role=static_cast<P2PPeerRole>(*p++);
    Get(p,e.wrap_nonce); Get(p,e.ciphertext); Get(p,e.auth_tag);
    if (!Valid(o) || static_cast<unsigned>(e.recipient_role)>1 ||
        e.recipient_peer_id!=(e.recipient_role==P2PPeerRole::Initiator?o.initiator_peer_id:o.responder_peer_id)) return false;
    output=o; envelope=e; return true;
}
bool OpenP2PRelayOfferRecipientV2(const std::string& encoded,const P2PId& session,const P2PId& peer,
    const P2PSessionExporter& exporter,P2PRelayOfferV2& output,P2PPeerRole& role,P2PPairSeed& seed) noexcept {
    P2PRelayOfferV2 o; P2PWrappedPairSeed e;
    if (!ParseP2PRelayOfferRecipientV2Hex(encoded,o,e)) return false;
    const auto local=e.recipient_role;
    if (peer!=e.recipient_peer_id || session!=(local==P2PPeerRole::Initiator?o.initiator_session_id:o.responder_session_id)) return false;
    P2PExporterContextV2 context{}; P2PExporterKey key{}; P2PWrapKey wrap{}; P2POfferHash hash{}; P2PPairSeed temporary{};
    const bool ok=BuildP2PExporterContextV2(o,local,context) && HashP2PRelayOfferV2(o,hash) &&
        Export(exporter,context,key) && WrapKey(key,hash,local,wrap) &&
        UnwrapP2PPairSeed(wrap,hash,peer,local,e,temporary);
    Clean(key); Clean(wrap); if (ok) { output=o; role=local; seed=temporary; }
    Clean(temporary); return ok;
}
}
