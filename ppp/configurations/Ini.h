#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class Ini final {
        public:
            class Section final {
            public:
                typedef std::map<ppp::string, ppp::string>              KeyValueTable;
                typedef KeyValueTable::iterator                         iterator;

            public:
                const ppp::string                                       Name;

            public:
                Section(const ppp::string& name) noexcept;

            public:
                ppp::string&                                            operator[](const ppp::string& key);

            public:
                iterator                                                begin() noexcept;
                iterator                                                end() noexcept;

            public:
                template <typename TValue>
                TValue                                                  GetValue(const ppp::string& key) noexcept;
                ppp::string                                             GetValue(const ppp::string& key) noexcept;

            public:
                int                                                     Count() noexcept;
                bool                                                    ContainsKey(const ppp::string& key) noexcept;
                bool                                                    RemoveValue(const ppp::string& key) noexcept;
                bool                                                    SetValue(const ppp::string& key, const ppp::string& value) noexcept;
                int                                                     GetAllKeys(std::vector<ppp::string>& keys) noexcept;
                int                                                     GetAllPairs(std::vector<std::pair<const ppp::string&, const ppp::string&> >& pairs) noexcept;
                ppp::string                                             ToString() const noexcept;

            private:
                mutable KeyValueTable                                   kv_;
            };
            typedef std::map<ppp::string, Section>                      SectionTable;
            typedef SectionTable::iterator                              iterator;

        public:
            Ini(const void* config) noexcept
                : Ini(config ? ppp::string((char*)config) : ppp::string()) {

            }
            Ini(const void* config, int length) noexcept
                : Ini(config&& length > 0 ? ppp::string((char*)config, length) : ppp::string()) {

            }
            Ini() noexcept;
            Ini(const ppp::string& config) noexcept;

        public:
            iterator                                                    begin() noexcept;
            iterator                                                    end() noexcept;

        public:
            Section&                                                    operator[](const ppp::string& section);

        public:
            int                                                         Count() noexcept;
            Section*                                                    Get(const ppp::string& section) noexcept;
            Section*                                                    Add(const ppp::string& section) noexcept;
            bool                                                        Remove(const ppp::string& section) noexcept;
            bool                                                        ContainsKey(const ppp::string& section) noexcept;
            int                                                         GetAllKeys(std::vector<ppp::string>& keys) noexcept;
            int                                                         GetAllPairs(std::vector<std::pair<const ppp::string&, const Section&> >& pairs) noexcept;
            ppp::string                                                 ToString() const noexcept;

        public:
            static std::shared_ptr<Ini>                                 LoadFile(const ppp::string& path) noexcept;
            static std::shared_ptr<Ini>                                 LoadFrom(const ppp::string& config) noexcept;

        private:
            mutable SectionTable                                        sections_;
        };
    }
}