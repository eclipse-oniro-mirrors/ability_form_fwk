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

namespace {
const std::string FORM_MODULE_WHITE_LIST_PATH = "/etc/form_fwk_module_white_list.json";
const std::string KEY_MODULE_ALLOW = "moduleAllowList";
const std::vector<std::string> MODULE_ALLOW_LIST = {
    "mediaquery",
    "display",
    "effectKit",
    "arkui.shape",
    "hilog",
    "url",
    "util",
    "util.ArrayList",
    "util.HashMap",
    "util.List",
    "util.json",
    "animator",
    "measure",
    "intl",
    "systemDateTime",
    "batteryInfo",
    "commonEventManager"
};
const std::vector<std::string> MODULE_ALLOW_WITH_API_LIST = {
    "i18n",
    "font",
    "multimedia.image",
    "deviceInfo",
    "window",
    "process",
    "graphics.text"
};
const std::vector<std::string> API_ALLOW_LIST = {
    "i18n.System.getSystemLanguage",
    "i18n.System.is24HourClock",
    "i18n.System.getSystemLocale",
    "i18n.System.getSystemRegion",
    "i18n.isRTL",
    "i18n.getTimeZone",
    "i18n.getCalendar"
    "i18n.Calendar.*",
    "i18n.TimeZone.*",
    "i18n.Unicode.*",
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
    "deviceInfo.deviceType",
    "deviceInfo.productModel",
    "window.WindowType.*",
    "window.AvoidAreaType.*",
    "window.WindowMode.*",
    "window.ColorSpace.*",
    "window.WindowStageEventType.*",
    "window.WindowEventType.*",
    "window.WindowLayoutMode.*",
    "window.Orientation.*",
    "window.BlurStyle.*",
    "window.WmErrorCode.*",
    "window.WMError.*",
    "window.WindowStatusType.*",
    "window.RectChangeReason.*",
    "window.MaximizePresentation.*",
    "window.ExtensionWindowAttribute.*",
    "window.ModalityType.*",
    "window._napiwrapper.*",
    "window.getTopWindow.*",
    "window.getLastWindow.*",
    "process.pid",
    "process.tid",
    "graphics.text.FontCollection.getLocalInstance",
    "graphics.text.FontCollection.loadFontSync",
    "graphics.text.FontCollection.unloadFontSync",
    "graphics.text.FontCollection.loadFont",
    "graphics.text.FontCollection.unloadFont",
};
} // namespace

std::vector<std::string> FormModuleChecker::modulesFromCfg_ = FormModuleChecker::GetModuleAllowList();

bool FormModuleChecker::CheckApiAllowList(const std::string& apiPath)
{
    for (const auto& item : API_ALLOW_LIST) {
        if (CheckApiWithSuffix(apiPath, item)) {
            return true;
        }
    }

    HILOG_DEBUG("api not allowed, apiPath: '%{public}s'", apiPath.c_str());
    return false;
}

bool FormModuleChecker::CheckApiWithSuffix(const std::string& apiPath, const std::string& item)
{
    HILOG_DEBUG("apiPath: '%{public}s', item: '%{public}s'", apiPath.c_str(), item.c_str());
    if (item.compare(0, apiPath.size(), apiPath) == 0) {
        return true;
    }
    const int32_t kSuffixLength = 2;
    if (item.size() >= kSuffixLength && item.substr(item.size() - kSuffixLength) == ".*") {
        const std::string path = item.substr(0, item.rfind('.'));
        if (apiPath.compare(0, path.size(), path) == 0) {
            return true;
        }
    }

    return false;
}

bool FormModuleChecker::CheckModuleLoadable(const char *moduleName,
    std::unique_ptr<ApiAllowListChecker> &apiAllowListChecker, bool isAppModule)
{
    if (isAppModule) {
        HILOG_ERROR("module is not system, moduleName= %{public}s", moduleName);
        return false;
    }

    // only check module
    for (const auto& item : modulesFromCfg_) {
        if (item == moduleName) {
            HILOG_DEBUG("load moduleName= %{public}s", moduleName);
            return true;
        }
    }
    for (const auto& item : MODULE_ALLOW_LIST) {
        if (item == moduleName) {
            HILOG_DEBUG("load moduleName= %{public}s", moduleName);
            return true;
        }
    }

    // check mnodule and api
    if (IsModuelAllowToLoad(moduleName)) {
        HILOG_DEBUG("module has been allowed by the allowlist in form, module name = %{public}s", moduleName);
        if (apiAllowListChecker == nullptr) {
            apiAllowListChecker = std::make_unique<ApiAllowListChecker>([](const std::string& apiPath) {
                return CheckApiAllowList(apiPath);
            });
        }
        return true;
    }
    HILOG_DEBUG("module can't load in form,moduleName= %{public}s", moduleName);
    return false;
}

bool FormModuleChecker::IsModuelAllowToLoad(const std::string& moduleName)
{
    for (const auto& item : MODULE_ALLOW_WITH_API_LIST) {
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

bool FormModuleChecker::DiskCheckOnly()
{
    return false;
}
