#pragma once

#include <ppp/stdafx.h>

const char*         chnroutes2_filepath_default();
time_t              chnroutes2_gettime();
ppp::string         chnroutes2_gettime(time_t time_);
bool                chnroutes2_saveiplist(const ppp::string& path_, const ppp::set<ppp::string>& ips_);
int                 chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_);
int                 chnroutes2_getiplist(ppp::set<ppp::string>& out_, const ppp::string& nation_, const ppp::string& iplist_);
ppp::string         chnroutes2_getiplist();
void                chnroutes2_getiplist_async(const ppp::function<void(ppp::string&)>& cb);
void                chnroutes2_sleep(int milliseconds);