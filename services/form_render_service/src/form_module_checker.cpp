/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "form_module_checker.h"

#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "config_policy_utils.h"

const std::string FORM_MODULE_WHITE_LIST_PATH = "/etc/form_fwk_module_white_list.json";
const std::string KEY_MODULE_ALLOW = "moduleAllowList";
const std::string KEY_MODULE_ALLOW_WITH_API = "moduleAllowWithApiList";
const std::string KEY_API_ALLOW = "apiAllowList";

std::map<std::string, std::vector<std::string>> FormModuleChecker::modulesFromCfg_ =
    FormModuleChecker::GetModuleAllowList();

bool FormModuleChecker::CheckApiAllowList(const std::string& apiPath)
{
    for (const auto& item : modulesFromCfg_[KEY_API_ALLOW]) {
        if (CheckApiWithSuffix(apiPath, item)) {
            return true;
        }
    }

    return false;
}

bool FormModuleChecker::CheckApiWithSuffix(const std::string& apiPath, const std::string& item)
{
    if (item.compare(0, apiPath.size(), apiPath) == 0) {
        HILOG_DEBUG("api allowed by allowlist: '%{public}s' matches '%{public}s'", apiPath.c_str(), item.c_str());
        return true;
    }
    const int32_t kSuffixLength = 2;
    if (item.size() >= kSuffixLength && item.substr(item.size() - kSuffixLength) == ".*") {
        const std::string path = item.substr(0, item.rfind('.'));
        if (apiPath.compare(0, path.size(), path) == 0) {
            HILOG_DEBUG("api allowed by allowlist: '%{public}s' matches '%{public}s'", apiPath.c_str(), item.c_str());
            return true;
        }
    }
    return false;
}

bool FormModuleChecker::CheckModuleLoadable(const char *moduleName,
    std::unique_ptr<ApiAllowListChecker> &apiAllowListChecker, bool isAppModule)
{
    if (isAppModule) {
        HILOG_INFO("module is not system, moduleName= %{public}s", moduleName);
        return false;
    }

    // only check module
    for (const auto& item : modulesFromCfg_[KEY_MODULE_ALLOW]) {
        if (item == moduleName) {
            HILOG_INFO("load moduleName= %{public}s", moduleName);
            return true;
        }
    }

    // check module and api
    if (IsModuelAllowToLoad(moduleName)) {
        HILOG_INFO("module has been allowed by the allowlist in form, module name = %{public}s", moduleName);
        if (apiAllowListChecker == nullptr) {
            apiAllowListChecker = std::make_unique<ApiAllowListChecker>([](const std::string& apiPath) {
                return CheckApiAllowList(apiPath);
            });
        }
        return true;
    }
    HILOG_INFO("module can't load in form,moduleName= %{public}s", moduleName);
    return false;
}

bool FormModuleChecker::IsModuelAllowToLoad(const std::string& moduleName)
{
    for (const auto& item : modulesFromCfg_[KEY_MODULE_ALLOW_WITH_API]) {
        if (item == moduleName) {
            return true;
        }
    }

    return false;
}

std::map<std::string, std::vector<std::string>> FormModuleChecker::GetModuleAllowList()
{
    HILOG_INFO("read moduleAllowList from config file");
    std::vector<std::string> result;
    char buf[MAX_PATH_LEN];
    char* path = GetOneCfgFile(FORM_MODULE_WHITE_LIST_PATH.c_str(), buf, MAX_PATH_LEN);
    if (path == nullptr || *path == '\0') {
        HILOG_ERROR("config file not found");
        return result;
    }
    std::ifstream file(path);
    if (!file.is_open()) {
        HILOG_ERROR("failed to open config file");
        return result;
    }
    HILOG_INFO("success to open config file");
    nlohmann::json jsonData;
    file >> jsonData;
    if (jsonData.contains(KEY_MODULE_ALLOW) && jsonData[KEY_MODULE_ALLOW].is_array()) {
        for (const auto& module : jsonData[KEY_MODULE_ALLOW]) {
            HILOG_INFO("read moduleAllowList module: %{public}s", std::string(module).c_str());
            result[KEY_MODULE_ALLOW].push_back(module);
        }
    }
    if (jsonData.contains(KEY_MODULE_ALLOW_WITH_API) && jsonData[KEY_MODULE_ALLOW_WITH_API].is_array()) {
        for (const auto& module : jsonData[KEY_MODULE_ALLOW_WITH_API]) {
            HILOG_INFO("read moduleAllowWithApiList module: %{public}s", std::string(module).c_str());
            result[KEY_MODULE_ALLOW_WITH_API].push_back(module);
        }
    }
    if (jsonData.contains(KEY_API_ALLOW) && jsonData[KEY_API_ALLOW].is_array()) {
        for (const auto& module : jsonData[KEY_API_ALLOW]) {
            HILOG_INFO("read apiAllowList api: %{public}s", std::string(api).c_str());
            result[KEY_API_ALLOW].push_back(api);
        }
    }
    file.close();
    return result;
}

bool FormModuleChecker::DiskCheckOnly()
{
    return false;
}