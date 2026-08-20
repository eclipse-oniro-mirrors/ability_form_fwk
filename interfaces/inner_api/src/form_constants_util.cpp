/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_constants_util.h"

#include <unordered_map>

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::unordered_map<Constants::Dimension, std::string> DIMENSION_MAP = {
    {Constants::Dimension::DIMENSION_1_2, "1*2"},
    {Constants::Dimension::DIMENSION_2_2, "2*2"},
    {Constants::Dimension::DIMENSION_2_4, "2*4"},
    {Constants::Dimension::DIMENSION_4_4, "4*4"},
    {Constants::Dimension::DIMENSION_2_1, "2*1"},
    {Constants::Dimension::DIMENSION_1_1, "1*1"},
    {Constants::Dimension::DIMENSION_6_4, "6*4"},
    {Constants::Dimension::DIMENSION_2_3, "2*3"},
    {Constants::Dimension::DIMENSION_3_3, "3*3"}
};

struct StatusInfo {
    std::string activeState;
    bool isSupportLauncher;
};

// A live-form status consists of two digits. The first digit describes the active state:
// '0' means INACTIVE, '1' means PAUSE, and '2' means ACTIVE. The second digit describes launcher support:
// '0' means unsupported and '1' means supported.
const std::unordered_map<std::string, StatusInfo> LIVE_FORM_STATUS_MAP = {
    {"00", {LiveFormState::INACTIVE, false}},
    {"01", {LiveFormState::INACTIVE, true}},
    {"10", {LiveFormState::PAUSE, false}},
    {"11", {LiveFormState::PAUSE, true}},
    {"20", {LiveFormState::ACTIVE, false}},
    {"21", {LiveFormState::ACTIVE, true}},
};
}

const char* FormConstantsUtil::GetDimensionString(Constants::Dimension dimension)
{
    auto iter = DIMENSION_MAP.find(dimension);
    if (iter == DIMENSION_MAP.end()) {
        return nullptr;
    }
    return iter->second.c_str();
}

const char* FormConstantsUtil::GetLiveFormActiveState(const std::string &status)
{
    auto iter = LIVE_FORM_STATUS_MAP.find(status);
    if (iter == LIVE_FORM_STATUS_MAP.end()) {
        return nullptr;
    }
    return iter->second.activeState.c_str();
}

bool FormConstantsUtil::IsLiveFormSupportLauncher(const std::string &status)
{
    auto iter = LIVE_FORM_STATUS_MAP.find(status);
    if (iter == LIVE_FORM_STATUS_MAP.end()) {
        return false;
    }
    return iter->second.isSupportLauncher;
}

bool FormConstantsUtil::IsConditionRefreshType(int32_t refreshType)
{
    return refreshType == Constants::REFRESHTYPE_NETWORKCHANGED;
}
}  // namespace AppExecFwk
}  // namespace OHOS
