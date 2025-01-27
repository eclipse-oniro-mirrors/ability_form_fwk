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

std::vector<std::string> FormModuleChecker::modulesFromCfg_ = FormModuleChecker::GetModuleAllowList();

bool FormModuleChecker::CheckApiAllowList(const std::string& apiPath)
{
    const std::vector<std::string> allowList = {
        "i18n.System.getSystemLanguage",
        "i18n.System.is24HourClock",
        "intl.Locale.*",
        "intl.DateTimeFormat.*",
        "effectKit.*",
        "font.registerFont",
        "multimedia.image.PixelMapFormat.*",
        "multimedia.image.Size.*",
        "multimedia.image.AlphaType.*",
        "multimedia.image.ScaleMode.*",
        "multimedia.image.Region.*",
        "multimedia.image.PositionArea.*",
        "multimedia.image.ImageInfo.*",
        "multimedia.image.DecodingOptions.*",
        "multimedia.image.InitializationOptions.*",
        "multimedia.image.SourceOptions.*",
        "multimedia.image.createImageSource",
        "multimedia.image.PixelMap.*",
        "multimedia.image.ImageSource.*",
        "arkui.shape.*"
    };

    for (const auto& item : allowList) {
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
    if (std::string(moduleName) == "mediaquery") {
        HILOG_INFO("load mediaquery");
        return true;
    }
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
    for (const auto& item : modulesFromCfg_) {
        if (item == moduleName) {
            return true;
        }
    }
    const std::vector<std::string> moduleAllowList = {
        "i18n",
        "intl",
        "effectKit",
        "font",
        "multimedia.image",
        "arkui.shape"
    };

    for (const auto& item : moduleAllowList) {
        if (item == moduleName) {
            return true;
        }
    }

    return false;
}

std::vector<std::string> FormModuleChecker::GetModuleAllowList()
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
            result.push_back(module);
        }
    }
    file.close();
    return result;
}
