#pragma once

#include <ppp/stdafx.h>

const char*         chnroutes2_filepath_default();
time_t              chnroutes2_gettime();
std::string         chnroutes2_gettime(time_t time_);
bool                chnroutes2_saveiplist(const std::string& path_, const std::set<std::string>& ips_);
int                 chnroutes2_getiplist(std::set<std::string>& out_);
int                 chnroutes2_getiplist(std::set<std::string>& out_, const std::string& iplist_);
std::string         chnroutes2_getiplist();
void                chnroutes2_getiplist_async(const ppp::function<void(std::string&)>& cb);
void                chnroutes2_sleep(int milliseconds);