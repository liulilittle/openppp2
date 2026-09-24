#define BOOST_TEST_MODULE transport_auth_keyring_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/TransportAuthConfiguration.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <fstream>
#include <string>
#include <vector>

using namespace ppp::configurations;

#if !defined(_WIN32)
namespace {
    class TempDirectory final {
    public:
        TempDirectory() {
            char path[] = "/tmp/openppp2-transport-auth-XXXXXX";
            char* result = mkdtemp(path);
            BOOST_REQUIRE(result != nullptr);
            path_ = result;
        }

        ~TempDirectory() {
            for (const std::string& file : files_) {
                unlink(file.c_str());
            }
            rmdir(path_.c_str());
        }

        std::string Write(const char* name, const std::string& contents, mode_t mode = 0600) {
            std::string path = path_ + "/" + name;
            std::ofstream stream(path.c_str(), std::ios::binary);
            stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
            stream.close();
            BOOST_REQUIRE(chmod(path.c_str(), mode) == 0);
            files_.emplace_back(path);
            return path;
        }

        std::string Path(const char* name) const { return path_ + "/" + name; }
        void Track(const std::string& path) { files_.emplace_back(path); }

    private:
        std::string path_;
        std::vector<std::string> files_;
    };

    static TransportAuthKeyMetadata Key(
        const char* id,
        TransportAuthKeyState state,
        const std::string& path) {
        TransportAuthKeyMetadata key;
        key.id = id;
        key.state = state;
        key.secret_file = path;
        return key;
    }

    static const std::string kSecretA(64, 'a');
    static const std::string kSecretB(64, 'b');
}

BOOST_AUTO_TEST_CASE(active_verify_and_revoked_lookup_is_fail_closed) {
    TempDirectory temp;
    const std::string active_path = temp.Write("active", kSecretA);
    const std::string verify_path = temp.Write("verify", kSecretB);
    const std::string missing_revoked_path = temp.Path("revoked-must-not-load");

    TransportAuthConfiguration config;
    config.keys.emplace_back(Key("current", TransportAuthKeyState::Active, active_path));
    config.keys.emplace_back(Key("previous", TransportAuthKeyState::VerifyOnly, verify_path));
    config.keys.emplace_back(Key("retired", TransportAuthKeyState::Revoked, missing_revoked_path));

    std::string error;
    auto snapshot = BuildTransportAuthKeyringSnapshot(config, &error);
    BOOST_REQUIRE_MESSAGE(snapshot, error.c_str());
    BOOST_TEST(snapshot->generation() > 0u);
    BOOST_REQUIRE(snapshot->active() != nullptr);
    BOOST_TEST(snapshot->active()->id == "current");
    BOOST_TEST(snapshot->FindEmitKey("current") != nullptr);
    BOOST_TEST(snapshot->FindEmitKey("previous") == nullptr);
    BOOST_TEST(snapshot->FindVerifyKey("current") != nullptr);
    BOOST_TEST(snapshot->FindVerifyKey("previous") != nullptr);
    BOOST_TEST(snapshot->FindVerifyKey("retired") == nullptr);
    BOOST_TEST(snapshot->FindVerifyKey("unknown") == nullptr);
    BOOST_TEST(snapshot->verify_key_count() == 1u);
}

BOOST_AUTO_TEST_CASE(metadata_validation_rejects_duplicates_and_invalid_active_sets) {
    TempDirectory temp;
    const std::string path = temp.Write("secret", kSecretA);
    std::string error;

    TransportAuthConfiguration duplicate;
    duplicate.keys.emplace_back(Key("same", TransportAuthKeyState::Active, path));
    duplicate.keys.emplace_back(Key("same", TransportAuthKeyState::VerifyOnly, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(duplicate, &error));

    TransportAuthConfiguration multiple;
    multiple.keys.emplace_back(Key("one", TransportAuthKeyState::Active, path));
    multiple.keys.emplace_back(Key("two", TransportAuthKeyState::Active, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(multiple, &error));

    TransportAuthConfiguration none;
    none.keys.emplace_back(Key("old", TransportAuthKeyState::VerifyOnly, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(none, &error));

    TransportAuthConfiguration too_many_verify;
    too_many_verify.keys.emplace_back(Key("active", TransportAuthKeyState::Active, path));
    too_many_verify.keys.emplace_back(Key("old-1", TransportAuthKeyState::VerifyOnly, path));
    too_many_verify.keys.emplace_back(Key("old-2", TransportAuthKeyState::VerifyOnly, path));
    too_many_verify.keys.emplace_back(Key("old-3", TransportAuthKeyState::VerifyOnly, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(too_many_verify, &error));

    TransportAuthConfiguration uppercase;
    uppercase.keys.emplace_back(Key("UpperCase", TransportAuthKeyState::Active, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(uppercase, &error));

    TransportAuthConfiguration too_long;
    const std::string long_id(64, 'a');
    too_long.keys.emplace_back(Key(long_id.c_str(), TransportAuthKeyState::Active, path));
    BOOST_TEST(!BuildTransportAuthKeyringSnapshot(too_long, &error));
}

BOOST_AUTO_TEST_CASE(secret_loader_rejects_mode_symlink_hex_and_length) {
    TempDirectory temp;
    std::string error;
    TransportAuthSecret secret;

    BOOST_TEST(LoadTransportAuthSecretFile(temp.Write("valid", kSecretA), secret, &error));
    BOOST_TEST(!LoadTransportAuthSecretFile(temp.Write("mode", kSecretA, 0640), secret, &error));
    BOOST_TEST(!LoadTransportAuthSecretFile(temp.Write("uppercase", std::string(64, 'A')), secret, &error));
    BOOST_TEST(!LoadTransportAuthSecretFile(temp.Write("short", std::string(63, 'a')), secret, &error));
    BOOST_TEST(!LoadTransportAuthSecretFile(temp.Write("newline", kSecretA + "\n"), secret, &error));

    const std::string target = temp.Write("target", kSecretB);
    const std::string link = temp.Path("link");
    BOOST_REQUIRE(symlink(target.c_str(), link.c_str()) == 0);
    temp.Track(link);
    BOOST_TEST(!LoadTransportAuthSecretFile(link, secret, &error));
}

BOOST_AUTO_TEST_CASE(successful_builds_advance_and_failed_build_retains_published_snapshot) {
    TempDirectory temp;
    const std::string path = temp.Write("secret", kSecretA);

    TransportAuthConfiguration valid;
    valid.keys.emplace_back(Key("active", TransportAuthKeyState::Active, path));
    std::shared_ptr<const TransportAuthKeyringSnapshot> published =
        BuildTransportAuthKeyringSnapshot(valid);
    BOOST_REQUIRE(published);
    const std::uint64_t published_generation = published->generation();
    BOOST_TEST(published_generation > 0u);

    auto reloaded = BuildTransportAuthKeyringSnapshot(valid);
    BOOST_REQUIRE(reloaded);
    BOOST_TEST(reloaded->generation() > published_generation);

    TransportAuthConfiguration invalid = valid;
    invalid.keys[0].secret_file = temp.Path("missing");
    auto candidate = BuildTransportAuthKeyringSnapshot(invalid);
    BOOST_TEST(!candidate);

    BOOST_TEST(published->generation() == published_generation);
    BOOST_REQUIRE(published->active() != nullptr);
    BOOST_TEST(published->active()->id == "active");
}
#else
BOOST_AUTO_TEST_CASE(windows_secret_file_loader_fails_closed) {
    TransportAuthSecret secret;
    std::string error;
    BOOST_TEST(!LoadTransportAuthSecretFile(
        "transport-auth-secret-must-not-be-opened", secret, &error));
    BOOST_TEST(error ==
        "transport-auth secret-file loading is unsupported on Windows");
}
#endif
