#define BOOST_TEST_MODULE transport_auth_configuration_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/AppConfiguration.h>

#include <json/json.h>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

using ppp::configurations::AppConfiguration;
using ppp::configurations::TransportAuthConfiguration;
using ppp::configurations::TransportAuthKeyState;

#if !defined(_WIN32)
namespace {
    class TempDirectory final {
    public:
        TempDirectory() {
            char path[] = "/tmp/openppp2-transport-auth-config-XXXXXX";
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

        std::string Write(const char* name, const std::string& contents) {
            const std::string path = path_ + "/" + name;
            std::ofstream stream(path.c_str(), std::ios::binary);
            stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
            stream.close();
            BOOST_REQUIRE(chmod(path.c_str(), 0600) == 0);
            files_.emplace_back(path);
            return path;
        }

        std::string Path(const char* name) const { return path_ + "/" + name; }

    private:
        std::string path_;
        std::vector<std::string> files_;
    };

    static Json::Value EnabledConfiguration(const std::string& active_path) {
        AppConfiguration defaults;
        Json::Value json = defaults.ToJson();
        json["client"]["transport-auth"]["enabled"] = true;
        json["transport-auth"]["keys"][0]["id"] = "current";
        json["transport-auth"]["keys"][0]["state"] = "active";
        json["transport-auth"]["keys"][0]["secret-file"] = active_path.c_str();
        return json;
    }
}
#endif

BOOST_AUTO_TEST_CASE(defaults_are_disabled_and_preserve_legacy_json_shape) {
    AppConfiguration config;

    BOOST_TEST(!config.client.transport_auth.enabled);
    BOOST_TEST(!config.server.transport_auth.enabled);
    BOOST_TEST(config.transport_auth.handshake_timeout_ms ==
        TransportAuthConfiguration::DefaultHandshakeTimeoutMs);
    BOOST_TEST(config.transport_auth.keys.empty());

    Json::Value json = config.ToJson();
    BOOST_TEST(!json.isMember("transport-auth"));
    BOOST_TEST(!json["client"].isMember("transport-auth"));
    BOOST_TEST(!json["server"].isMember("transport-auth"));
}

BOOST_AUTO_TEST_CASE(timeout_is_clamped_to_the_supported_range) {
    AppConfiguration config;
    config.transport_auth.handshake_timeout_ms = 1;
    BOOST_REQUIRE(config.Normalize());
    BOOST_TEST(config.transport_auth.handshake_timeout_ms ==
        TransportAuthConfiguration::MinHandshakeTimeoutMs);

    config.transport_auth.handshake_timeout_ms = 50000;
    BOOST_REQUIRE(config.Normalize());
    BOOST_TEST(config.transport_auth.handshake_timeout_ms ==
        TransportAuthConfiguration::MaxHandshakeTimeoutMs);
}

BOOST_AUTO_TEST_CASE(enabled_configuration_roundtrips_metadata_without_secret_material) {
#if !defined(_WIN32)
    TempDirectory temp;
    const std::string active_path = temp.Write("current", std::string(64, 'a'));
    const std::string verify_path = temp.Write("previous", std::string(64, 'b'));
    Json::Value json = EnabledConfiguration(active_path);
    json["transport-auth"]["handshake-timeout-ms"] = 7000;
    json["transport-auth"]["keys"][1]["id"] = "previous";
    json["transport-auth"]["keys"][1]["state"] = "verify-only";
    json["transport-auth"]["keys"][1]["secret-file"] = verify_path.c_str();
    json["transport-auth"]["keys"][2]["id"] = "retired";
    json["transport-auth"]["keys"][2]["state"] = "revoked";
    json["transport-auth"]["keys"][2]["secret-file"] = "/must/not/be/read";
    json["server"]["transport-auth"]["enabled"] = true;

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));
    BOOST_TEST(loaded.transport_auth.handshake_timeout_ms == 7000);
    BOOST_TEST(loaded.client.transport_auth.enabled);
    BOOST_TEST(loaded.server.transport_auth.enabled);
    BOOST_REQUIRE(loaded.transport_auth.keys.size() == 3u);
    BOOST_REQUIRE(loaded.transport_auth_keyring);
    BOOST_TEST(loaded.transport_auth_keyring->generation() > 0u);
    BOOST_REQUIRE(loaded.transport_auth_keyring->active() != nullptr);
    BOOST_TEST(loaded.transport_auth_keyring->active()->id == "current");
    BOOST_TEST(static_cast<int>(loaded.transport_auth.keys[0].state) ==
        static_cast<int>(TransportAuthKeyState::Active));
    BOOST_TEST(static_cast<int>(loaded.transport_auth.keys[1].state) ==
        static_cast<int>(TransportAuthKeyState::VerifyOnly));
    BOOST_TEST(static_cast<int>(loaded.transport_auth.keys[2].state) ==
        static_cast<int>(TransportAuthKeyState::Revoked));

    BOOST_REQUIRE(unlink(active_path.c_str()) == 0);
    BOOST_REQUIRE(unlink(verify_path.c_str()) == 0);
    Json::Value roundtrip = loaded.ToJson();
    BOOST_TEST(roundtrip["transport-auth"]["handshake-timeout-ms"].asInt() == 7000);
    BOOST_TEST(!roundtrip["transport-auth"].isMember("fresh-fallback"));
    BOOST_TEST(roundtrip["transport-auth"]["keys"][0]["secret-file"].asString() == active_path.c_str());
    BOOST_TEST(roundtrip["client"]["transport-auth"]["enabled"].asBool());
    BOOST_TEST(roundtrip["server"]["transport-auth"]["enabled"].asBool());
    BOOST_TEST(!roundtrip.isMember("transport-auth-keyring"));
    BOOST_REQUIRE(loaded.transport_auth_keyring);
    BOOST_TEST(loaded.transport_auth_keyring->active()->id == "current");

    const ppp::string serialized = loaded.ToString();
    BOOST_TEST(serialized.find(ppp::string(64, 'a')) == ppp::string::npos);
    BOOST_TEST(serialized.find(ppp::string(64, 'b')) == ppp::string::npos);
#else
    BOOST_TEST(true);
#endif
}

BOOST_AUTO_TEST_CASE(failed_keyring_build_does_not_publish_or_replace_snapshot) {
#if !defined(_WIN32)
    TempDirectory temp;
    const std::string active_path = temp.Write("active", std::string(64, 'c'));

    AppConfiguration missing;
    Json::Value missing_json = EnabledConfiguration(temp.Path("missing"));
    BOOST_TEST(!missing.Load(missing_json));
    BOOST_TEST(!missing.transport_auth_keyring);

    AppConfiguration loaded;
    Json::Value valid_json = EnabledConfiguration(active_path);
    BOOST_REQUIRE(loaded.Load(valid_json));
    const auto published = loaded.transport_auth_keyring;
    BOOST_REQUIRE(published);
    const std::uint64_t published_generation = published->generation();
    BOOST_TEST(published_generation > 0u);
    loaded.transport_auth.keys[0].secret_file = temp.Path("missing-after-load");
    BOOST_TEST(!loaded.Normalize());
    BOOST_TEST(loaded.transport_auth_keyring == published);
    BOOST_TEST(loaded.transport_auth_keyring->generation() == published_generation);

    loaded.transport_auth.keys[0].secret_file = active_path;
    BOOST_REQUIRE(loaded.Normalize());
    BOOST_REQUIRE(loaded.transport_auth_keyring);
    BOOST_TEST(loaded.transport_auth_keyring != published);
    BOOST_TEST(loaded.transport_auth_keyring->generation() > published_generation);

    loaded.client.transport_auth.enabled = false;
    loaded.server.transport_auth.enabled = false;
    BOOST_REQUIRE(loaded.Normalize());
    BOOST_TEST(!loaded.transport_auth_keyring);
#else
    BOOST_TEST(true);
#endif
}

BOOST_AUTO_TEST_CASE(enabled_configuration_requires_one_active_key) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["client"]["transport-auth"]["enabled"] = true;
    json["transport-auth"]["keys"] = Json::Value(Json::arrayValue);

    AppConfiguration loaded;
    BOOST_TEST(!loaded.Load(json));
}

BOOST_AUTO_TEST_CASE(invalid_key_state_is_rejected) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["transport-auth"]["keys"][0]["id"] = "bad";
    json["transport-auth"]["keys"][0]["state"] = "retiring";
    json["transport-auth"]["keys"][0]["secret-file"] = "/tmp/not-read";

    AppConfiguration loaded;
    BOOST_TEST(!loaded.Load(json));
}
