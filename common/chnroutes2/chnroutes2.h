#pragma once

#include <ppp/stdafx.h>

ppp::string         chnroutes2_cacertpath_default() noexcept;
const char*         chnroutes2_filepath_default() noexcept;
time_t              chnroutes2_gettime() noexcept;
ppp::string         chnroutes2_gettime(time_t time_) noexcept;
ppp::string         chnroutes2_toiplist(const ppp::set<ppp::string>& ips_) noexcept;
bool                chnroutes2_saveiplist(const ppp::string& path_, const ppp::set<ppp::string>& ips_) noexcept;
int                 chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_) noexcept;
int                 chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_, const ppp::string& iplist_) noexcept;
ppp::string         chnroutes2_getiplist() noexcept;
void                chnroutes2_getiplist_async(const ppp::function<void(ppp::string&)>& cb) noexcept(false);
void                chnroutes2_sleep(int milliseconds) noexcept;
bool                chnroutes2_equals(const ppp::set<ppp::string>& xs, const ppp::set<ppp::string>& ys) noexcept;