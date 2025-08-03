/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "form_info.h"
#include "form_info_filter.h"
#include "data_center/form_info/form_info_storage.h"
#include "data_center/form_cust_config_mgr.h"

#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AAFwk {
namespace {
const std::string JSON_KEY_USER_ID = "userId";
const std::string JSON_KEY_FORM_INFO = "formInfos";
const int32_t DEFAULT_RECT_SHAPE = 1;
} // namespace

FormInfoStorage::FormInfoStorage(int32_t userId, const std::vector<AppExecFwk::FormInfo> &formInfos)
{
    this->userId = userId;
    for (const auto &item : formInfos) {
        this->formInfos.push_back(item);
    }
}

void FormInfoStorage::GetAllFormsInfo(int32_t userId, std::vector<AppExecFwk::FormInfo> &formInfos) const
{
    HILOG_INFO("GetAllFormsInfo, caller userId is %{public}d, this userId is %{public}d", userId, this->userId);
    if (this->userId != userId && this->userId != AppExecFwk::Constants::DEFAULT_USERID) {
        HILOG_ERROR("Invalid userId");
        return;
    }

    for (const auto &item : this->formInfos) {
        if (IsFunInterFormInfoFiltered(item)) {
            continue;
        }
        formInfos.push_back(item);
    }
}

static bool find_match_dimensions(const std::vector<int32_t> &targetDimensions,
    const std::vector<int32_t> &supportDimensions, std::vector<int32_t> &results)
{
    for (const auto &val : supportDimensions) {
        auto it = std::find(targetDimensions.begin(), targetDimensions.end(), val);
        if (it != targetDimensions.end()) {
            results.emplace_back(val);
        }
    }
    return !results.empty();
}

static bool find_match_shapes(const std::vector<int32_t> &targetShapes, const std::vector<int32_t> &supportShapes)
{
    for (const auto &val : supportShapes) {
        auto it = std::find(targetShapes.begin(), targetShapes.end(), val);
        if (it != targetShapes.end()) {
            return true;
        }
    }
    return false;
}

static bool find_rect_shape(const std::vector<int32_t> &supportShapes)
{
    for (const auto &val : supportShapes) {
        if (val == DEFAULT_RECT_SHAPE) {
            return true;
        }
    }
    return false;
}

void FormInfoStorage::GetFormsInfoByFilter(int32_t userId,
    const AppExecFwk::FormInfoFilter &filter, std::vector<AppExecFwk::FormInfo> &formInfos) const
{
    HILOG_INFO("caller userId is:%{public}d, this userId is %{public}d", userId, this->userId);
    if (this->userId != userId && this->userId != AppExecFwk::Constants::DEFAULT_USERID) {
        HILOG_ERROR("Invalid userId");
        return;
    }
    for (const auto &item : this->formInfos) {
        if (!filter.moduleName.empty() && filter.moduleName != item.moduleName) {
            continue;
        }
        if (filter.supportShapes.empty() && !find_rect_shape(item.supportShapes)) {
            HILOG_WARN("Empty supportShape,without rectShape");
            continue;
        }
        if (!filter.supportShapes.empty() && !find_match_shapes(filter.supportShapes, item.supportShapes)) {
            continue;
        }
        if (IsFunInterFormInfoFiltered(item)) {
            continue;
        }
        if (filter.supportDimensions.empty()) {
            formInfos.emplace_back(item);
        } else {
            std::vector<int32_t> results;
            if (find_match_dimensions(filter.supportDimensions, item.supportDimensions, results)) {
                AppExecFwk::FormInfo formInfo = item;
                formInfo.supportDimensions = results;
                formInfos.emplace_back(formInfo);
            }
        }
    }
}

void FormInfoStorage::GetFormsInfoByModule(int32_t userId, const std::string &moduleName,
    std::vector<AppExecFwk::FormInfo> &formInfos) const
{
    HILOG_INFO("caller userId is:%{public}d, this userId is %{public}d", userId, this->userId);
    if (this->userId != userId && this->userId != AppExecFwk::Constants::DEFAULT_USERID) {
        HILOG_ERROR("Invalid userId");
        return;
    }
    for (const auto &item : this->formInfos) {
        if (IsFunInterFormInfoFiltered(item)) {
            continue;
        }
        if (item.moduleName == moduleName) {
            formInfos.push_back(item);
        }
    }
}

bool FormInfoStorage::IsFunInterFormInfoFiltered(const AppExecFwk::FormInfo &formInfo) const
{
    if (formInfo.funInteractionParams.targetBundleName.empty() && !IsGameCard(formInfo)) {
        return false;
    }

    if (AppExecFwk::FormCustConfigMgr::GetInstance().IsSupportFunInteraction()) {
        return false;
    }

    if (IsGameCard(formInfo) && AppExecFwk::FormCustConfigMgr::GetInstance().IsSupportGameCard()) {
        return false;
    }

    HILOG_ERROR("fms not support fun interaction of bundleName: %{public}s", formInfo.bundleName.c_str());
    return true;
}

bool FormInfoStorage::IsGameCard(const AppExecFwk::FormInfo &formInfo) const
{
    for (auto it = formInfo.customizeDatas.begin(); it != formInfo.customizeDatas.end(); ++it) {
        if (it->name == AppExecFwk::Constants::PARAM_GAME_CARD_KEY &&
            it->value == AppExecFwk::Constants::PARAM_GAME_CARD_TYPE) {
            return true;
        }
    }
    return false;
}

void to_json(nlohmann::json &jsonObject, const FormInfoStorage &formInfoStorage)
{
    jsonObject = nlohmann::json {
        {JSON_KEY_USER_ID, formInfoStorage.userId},
        {JSON_KEY_FORM_INFO, formInfoStorage.formInfos}
    };
}

void from_json(const nlohmann::json &jsonObject, FormInfoStorage &formInfoStorage)
{
    if (jsonObject.contains(JSON_KEY_USER_ID) && !jsonObject.at(JSON_KEY_USER_ID).is_null() &&
        jsonObject.at(JSON_KEY_USER_ID).is_number_integer()) {
        formInfoStorage.userId = jsonObject.at(JSON_KEY_USER_ID).get<int32_t>();
    }
    if (jsonObject.contains(JSON_KEY_FORM_INFO) && !jsonObject.at(JSON_KEY_FORM_INFO).is_null() &&
        jsonObject.at(JSON_KEY_FORM_INFO).is_array()) {
        formInfoStorage.formInfos = jsonObject.at(JSON_KEY_FORM_INFO).get<std::vector<AppExecFwk::FormInfo>>();
    }
}
} // namespace AAFwk
} // namespace OHOS
