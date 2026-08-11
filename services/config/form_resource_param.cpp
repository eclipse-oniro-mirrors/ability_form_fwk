/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_resource_param.h"

#include "fms_log_wrapper.h"
#include "parameter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t MAX_LEN = 128;
constexpr const char *SYSTEM_LANGUAGE = "persist.global.locale";
constexpr const char *SYSTEM_COLOR_MODE = "persist.ace.darkmode";
constexpr const char *BOOT_BOPD_MODE = "ohos.boot.bopd.mode";
constexpr const char *DEFAULT_LANGUAGE = "zh-Hans";
constexpr const char *DEFAULT_COLOR_MODE_LIGHT = "light";

constexpr const char *BOPD_BEFORE_DL = "0x2";
constexpr const char *BOPD_STG_RO_BEFORE_DL = "0x3";
constexpr const char *BOPD_HW_DEG_BEFORE_DL = "0x6";
constexpr const char *BOPD_STG_RO_HW_DEG_BEFORE_DL = "0x7";
constexpr const char *BOPD_AFTER_DL = "0xa";
constexpr const char *BOPD_HW_DEG_AFTER_DL = "0xe";
constexpr const char *BOPD_HW_DEG_VIA_ERECOVERY = "0xf";

constexpr const char *VALID_BOPD_MODE[] = {
    BOPD_BEFORE_DL,
    BOPD_STG_RO_BEFORE_DL,
    BOPD_HW_DEG_BEFORE_DL,
    BOPD_STG_RO_HW_DEG_BEFORE_DL,
    BOPD_AFTER_DL,
    BOPD_HW_DEG_AFTER_DL,
    BOPD_HW_DEG_VIA_ERECOVERY
};
}

std::string FormResourceParam::GetSystemLanguage()
{
    std::string language = GetSystemParam(SYSTEM_LANGUAGE);
    return language.empty() ? DEFAULT_LANGUAGE : language;
}

std::string FormResourceParam::GetSystemColorMode()
{
    std::string mode = GetSystemParam(SYSTEM_COLOR_MODE);
    return mode.empty() ? DEFAULT_COLOR_MODE_LIGHT : mode;
}

bool FormResourceParam::IsBopdMode()
{
    std::string mode = GetSystemParam(BOOT_BOPD_MODE);
    for (const auto iter : VALID_BOPD_MODE) {
        if (mode == iter) {
            return true;
        }
    }
    return false;
}

std::string FormResourceParam::GetSystemParam(const char *key)
{
    char value[MAX_LEN] = {0};
    int32_t ret = GetParameter(key, "", value, MAX_LEN);
    if (ret <= 0) {
        HILOG_ERROR("GetParameter:%{public}s failed", key);
        return "";
    }
    return std::string(value);
}
} // AppExecFwk
} // OHOS
