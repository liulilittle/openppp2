#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <memory>

namespace ppp::p2p {
namespace {

template <std::size_t N>
bool Random(std::array<std::uint8_t, N>& output) noexcept {
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

void Cleanse(P2PRelayOfferSecrets& secrets) noexcept {
    OPENSSL_cleanse(secrets.offer_id.data(), secrets.offer_id.size());
    OPENSSL_cleanse(
        secrets.connection_epoch.data(), secrets.connection_epoch.size());
    OPENSSL_cleanse(secrets.pair_seed.data(), secrets.pair_seed.size());
    OPENSSL_cleanse(
        secrets.initiator_wrap_nonce.data(),
        secrets.initiator_wrap_nonce.size());
    OPENSSL_cleanse(
        secrets.responder_wrap_nonce.data(),
        secrets.responder_wrap_nonce.size());
}

P2PRelayOfferV1 MakeOffer(
    const P2PRelayOfferInput& input,
    const P2PRelayOfferSecrets& secrets) noexcept {
    P2PRelayOfferV1 offer;
    offer.offer_id = secrets.offer_id;
    offer.initiator_session_id = input.initiator_session_id;
    offer.responder_session_id = input.responder_session_id;
    offer.initiator_peer_id = input.initiator_peer_id;
    offer.responder_peer_id = input.responder_peer_id;
    offer.connection_epoch = secrets.connection_epoch;
    offer.ttl_seconds = input.ttl_seconds;
    offer.candidate_set_hash = input.candidate_set_hash;
    return offer;
}

bool Export(
    const P2PSessionExporter& exporter,
    const P2PExporterContext& context,
    P2PExporterKey& output) noexcept {
    if (!exporter) {
        return false;
    }
    try {
        return exporter(
            P2PWrapExporterLabel,
            context.data(), context.size(),
            output.data(), output.size());
    }
    catch (...) {
        return false;
    }
}

class AsyncRelayOffer final
    : public std::enable_shared_from_this<AsyncRelayOffer> {
public:
    AsyncRelayOffer(
        const P2PRelayOfferInput& input,
        const P2PAsyncSessionExporter& initiator_exporter,
        const P2PAsyncSessionExporter& responder_exporter,
        const P2PRelayOfferCompletion& completion)
        : input_(input),
          initiator_exporter_(initiator_exporter),
          responder_exporter_(responder_exporter),
          completion_(completion) {}

    ~AsyncRelayOffer() noexcept {
        Clean();
    }

    void Start() noexcept {
        const bool random_ready = Random(secrets_.offer_id) &&
            Random(secrets_.connection_epoch) &&
            Random(secrets_.pair_seed) &&
            Random(secrets_.initiator_wrap_nonce) &&
            Random(secrets_.responder_wrap_nonce);
        const auto offer = MakeOffer(input_, secrets_);
        if (!random_ready ||
            !BuildP2PExporterContext(
                offer, P2PPeerRole::Initiator, initiator_context_) ||
            !BuildP2PExporterContext(
                offer, P2PPeerRole::Responder, responder_context_)) {
            Complete(false, {});
            return;
        }

        auto self = shared_from_this();
        auto exporter = initiator_exporter_;
        try {
            exporter(
                P2PWrapExporterLabel, initiator_context_, initiator_key_,
                [self](bool ok) noexcept { self->OnInitiator(ok); });
        }
        catch (...) {
            OnInitiator(false);
        }
    }

private:
    void OnInitiator(bool ok) noexcept {
        int expected = 0;
        if (completed_.load(std::memory_order_acquire) ||
            !stage_.compare_exchange_strong(
                expected, 1, std::memory_order_acq_rel)) {
            return;
        }
        if (!ok) {
            Complete(false, {});
            return;
        }

        auto self = shared_from_this();
        auto exporter = responder_exporter_;
        try {
            exporter(
                P2PWrapExporterLabel, responder_context_, responder_key_,
                [self](bool exported) noexcept {
                    self->OnResponder(exported);
                });
        }
        catch (...) {
            OnResponder(false);
        }
    }

    void OnResponder(bool ok) noexcept {
        int expected = 1;
        if (completed_.load(std::memory_order_acquire) ||
            !stage_.compare_exchange_strong(
                expected, 2, std::memory_order_acq_rel)) {
            return;
        }

        P2PRelayOfferBundle bundle;
        const bool built = ok && BuildP2PRelayOfferBundle(
            input_, initiator_key_, responder_key_, secrets_, bundle);
        Complete(built, bundle);
    }

    void Complete(bool ok, const P2PRelayOfferBundle& bundle) noexcept {
        if (completed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        auto completion = std::move(completion_);
        initiator_exporter_ = {};
        responder_exporter_ = {};
        Clean();
        if (completion) {
            try {
                completion(ok, bundle);
            }
            catch (...) {
            }
        }
    }

    void Clean() noexcept {
        OPENSSL_cleanse(initiator_key_.data(), initiator_key_.size());
        OPENSSL_cleanse(responder_key_.data(), responder_key_.size());
        Cleanse(secrets_);
    }

private:
    P2PRelayOfferInput input_;
    P2PAsyncSessionExporter initiator_exporter_;
    P2PAsyncSessionExporter responder_exporter_;
    P2PRelayOfferCompletion completion_;
    P2PRelayOfferSecrets secrets_;
    P2PExporterContext initiator_context_{};
    P2PExporterContext responder_context_{};
    P2PExporterKey initiator_key_{};
    P2PExporterKey responder_key_{};
    std::atomic<int> stage_{0};
    std::atomic_bool completed_{false};
};

bool ValidCandidate(const P2PCandidateV1& candidate) noexcept {
    if (candidate.port == 0 ||
        (candidate.address_family != 4 && candidate.address_family != 6)) {
        return false;
    }
    bool any = false;
    for (const auto byte : candidate.address) {
        any = any || byte != 0;
    }
    if (!any) {
        return false;
    }
    const bool mapped = std::all_of(
            candidate.address.begin(), candidate.address.begin() + 10,
            [](std::uint8_t byte) { return byte == 0; }) &&
        candidate.address[10] == 0xff && candidate.address[11] == 0xff;
    if (candidate.address_family == 4) {
        const bool payload_nonzero = std::any_of(
            candidate.address.begin() + 12, candidate.address.end(),
            [](std::uint8_t byte) { return byte != 0; });
        return mapped && payload_nonzero;
    }
    return !mapped;
}

}

bool BuildP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PExporterKey& initiator_exporter,
    const P2PExporterKey& responder_exporter,
    const P2PRelayOfferSecrets& secrets,
    P2PRelayOfferBundle& output) noexcept {
    P2PRelayOfferBundle bundle;
    bundle.offer = MakeOffer(input, secrets);

    P2POfferHash offer_hash{};
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    const bool ok = HashP2PRelayOffer(bundle.offer, offer_hash) &&
        DeriveP2PWrapKey(
            initiator_exporter, offer_hash,
            P2PPeerRole::Initiator, initiator_key) &&
        DeriveP2PWrapKey(
            responder_exporter, offer_hash,
            P2PPeerRole::Responder, responder_key) &&
        WrapP2PPairSeed(
            initiator_key, offer_hash, input.initiator_peer_id,
            P2PPeerRole::Initiator, secrets.initiator_wrap_nonce,
            secrets.pair_seed, bundle.initiator_envelope) &&
        WrapP2PPairSeed(
            responder_key, offer_hash, input.responder_peer_id,
            P2PPeerRole::Responder, secrets.responder_wrap_nonce,
            secrets.pair_seed, bundle.responder_envelope);

    OPENSSL_cleanse(initiator_key.data(), initiator_key.size());
    OPENSSL_cleanse(responder_key.data(), responder_key.size());
    if (!ok) {
        return false;
    }
    output = bundle;
    return true;
}

bool CreateP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PSessionExporter& initiator_exporter,
    const P2PSessionExporter& responder_exporter,
    P2PRelayOfferBundle& output) noexcept {
    P2PRelayOfferSecrets secrets;
    P2PExporterContext initiator_context{};
    P2PExporterContext responder_context{};
    P2PExporterKey initiator_key{};
    P2PExporterKey responder_key{};
    const bool random_ready = Random(secrets.offer_id) &&
        Random(secrets.connection_epoch) &&
        Random(secrets.pair_seed) &&
        Random(secrets.initiator_wrap_nonce) &&
        Random(secrets.responder_wrap_nonce);
    const auto offer = MakeOffer(input, secrets);
    const bool ok = random_ready &&
        BuildP2PExporterContext(
            offer, P2PPeerRole::Initiator, initiator_context) &&
        BuildP2PExporterContext(
            offer, P2PPeerRole::Responder, responder_context) &&
        Export(initiator_exporter, initiator_context, initiator_key) &&
        Export(responder_exporter, responder_context, responder_key) &&
        BuildP2PRelayOfferBundle(
            input, initiator_key, responder_key, secrets, output);
    OPENSSL_cleanse(initiator_key.data(), initiator_key.size());
    OPENSSL_cleanse(responder_key.data(), responder_key.size());
    Cleanse(secrets);
    return ok;
}

bool CreateP2PRelayOfferBundleAsync(
    const P2PRelayOfferInput& input,
    const P2PAsyncSessionExporter& initiator_exporter,
    const P2PAsyncSessionExporter& responder_exporter,
    const P2PRelayOfferCompletion& completion) noexcept {
    if (!initiator_exporter || !responder_exporter || !completion) {
        return false;
    }
    try {
        auto operation = std::make_shared<AsyncRelayOffer>(
            input, initiator_exporter, responder_exporter, completion);
        operation->Start();
        return true;
    }
    catch (...) {
        return false;
    }
}

P2PAsyncSessionExporter ScheduleP2PSessionExporter(
    const P2PTaskScheduler& scheduler,
    const P2PSessionExporter& exporter) noexcept {
    if (!scheduler || !exporter) {
        return {};
    }
    try {
        return [scheduler, exporter](
                   const char* label,
                   const P2PExporterContext& context,
                   P2PExporterKey& output,
                   const P2PExportCompletion& completion) {
            auto finished = std::make_shared<std::atomic_bool>(false);
            const auto finish = [finished, completion](bool ok) noexcept {
                if (finished->exchange(true, std::memory_order_acq_rel) ||
                    !completion) {
                    return;
                }
                try {
                    completion(ok);
                }
                catch (...) {
                }
            };
            const std::string copied_label = label ? label : "";
            const P2PExporterContext copied_context = context;
            const P2PTask task = [
                exporter, copied_label, copied_context,
                &output, finish]() noexcept {
                bool ok = false;
                try {
                    ok = exporter(
                        copied_label.c_str(),
                        copied_context.data(), copied_context.size(),
                        output.data(), output.size());
                }
                catch (...) {
                }
                finish(ok);
            };
            bool scheduled = false;
            try {
                scheduled = scheduler(task);
            }
            catch (...) {
            }
            if (!scheduled) {
                finish(false);
            }
        };
    }
    catch (...) {
        return {};
    }
}

bool HashP2PCandidateSet(
    const std::vector<P2PCandidateV1>& candidates,
    P2POfferHash& output) noexcept {
    using CandidateBytes = std::array<std::uint8_t, 19>;
    std::vector<CandidateBytes> records;
    try {
        records.reserve(candidates.size());
        for (const auto& candidate : candidates) {
            if (!ValidCandidate(candidate)) {
                return false;
            }
            CandidateBytes record{};
            record[0] = candidate.address_family;
            std::copy(
                candidate.address.begin(), candidate.address.end(),
                record.begin() + 1);
            record[17] = static_cast<std::uint8_t>(candidate.port >> 8);
            record[18] = static_cast<std::uint8_t>(candidate.port);
            records.emplace_back(record);
        }
        std::sort(records.begin(), records.end());
        records.erase(std::unique(records.begin(), records.end()), records.end());
    }
    catch (...) {
        return false;
    }

    P2POfferHash digest{};
    unsigned int digest_size = 0;
    static constexpr std::uint8_t empty = 0;
    const auto* data = records.empty()
        ? &empty
        : reinterpret_cast<const std::uint8_t*>(records.data());
    const std::size_t size = records.size() * CandidateBytes{}.size();
    const bool ok = EVP_Digest(
            data, size, digest.data(), &digest_size, EVP_sha256(), nullptr) == 1 &&
        digest_size == digest.size();
    if (ok) {
        output = digest;
    }
    OPENSSL_cleanse(digest.data(), digest.size());
    return ok;
}

}
