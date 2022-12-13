/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_info_rdb_storage_mgr.h"

#include <cinttypes>
#include <thread>
#include <unistd.h>
#include "form_constants.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t MAX_TIMES = 600; // 600 * 100ms = 1min
constexpr int32_t SLEEP_INTERVAL = 100 * 1000; // 100ms
const std::string FORM_INFO_PREFIX = "formInfo_";
const std::string FORM_ID_PREFIX = "formId_";
} // namespace

FormInfoRdbStorageMgr::FormInfoRdbStorageMgr()
{
    FormRdbConfig formRdbConfig;
    rdbDataManager_ = std::make_shared<FormRdbDataMgr>(formRdbConfig);
    rdbDataManager_->Init();
    HILOG_DEBUG("FormInfoRdbStorageMgr is created");
}

FormInfoRdbStorageMgr::~FormInfoRdbStorageMgr()
{
    HILOG_DEBUG("FormInfoRdbStorageMgr is deleted");
}

ErrCode FormInfoRdbStorageMgr::LoadFormInfos(std::vector<std::pair<std::string, std::string>> &formInfoStorages)
{
    HILOG_DEBUG("FormInfoAllRdbStorageMgr load all form infos");
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    std::unordered_map<std::string, std::string> value;
    ErrCode result;
    result = rdbDataManager_->QueryData(FORM_INFO_PREFIX, value);
    if (result != ERR_OK) {
        HILOG_ERROR("get entries error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    for (const auto &item: value) {
        formInfoStorages.emplace_back(item.first.substr(FORM_INFO_PREFIX.length()), item.second);
    }

    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::RemoveBundleFormInfos(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("FormInfoRdbStorageMgr remove form info, bundleName=%{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    std::string key = std::string().append(FORM_INFO_PREFIX).append(bundleName);
    ErrCode result;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        result = rdbDataManager_->DeleteData(key);
    }

    if (result != ERR_OK) {
        HILOG_ERROR("remove formInfoStorages from rdbStore error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::UpdateBundleFormInfos(const std::string &bundleName, const std::string &formInfoStorages)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("FormInfoRdbStorageMgr update form info, bundleName=%{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    std::string key = std::string().append(FORM_INFO_PREFIX).append(bundleName);
    ErrCode result;
    std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
    std::string value = formInfoStorages;
    result = rdbDataManager_->InsertData(key, value);
    if (result != ERR_OK) {
        HILOG_ERROR("update formInfoStorages to rdbStore error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

bool FormInfoRdbStorageMgr::CheckRdbStore()
{
    if(rdbDataManager_ == nullptr) {
        HILOG_ERROR("rdbDataManager is null");
        return false;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        ErrCode result = rdbDataManager_->Init();
        if (result == ERR_OK) {
            return true;
        }
        HILOG_DEBUG("CheckRdbStore, Times: %{public}d", tryTimes);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }
    return false;
}

void FormInfoRdbStorageMgr::SaveEntries(
    const std::unordered_map<std::string, std::string> &value, std::vector<InnerFormInfo> &innerFormInfos)
{
    for (const auto &item : value) {
        InnerFormInfo innerFormInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(item.second, nullptr, false);
        if (jsonObject.is_discarded() || innerFormInfo.FromJson(jsonObject) != true) {
            HILOG_ERROR("error key: %{private}s", item.first.c_str());
            {
                std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
                if (!CheckRdbStore()) {
                    HILOG_ERROR("RdbStore is nullptr");
                    return;
                }
                rdbDataManager_->DeleteData(item.first);
            }
            continue;
        }

        if (std::find(innerFormInfos.begin(), innerFormInfos.end(), innerFormInfo) == innerFormInfos.end()) {
            innerFormInfos.emplace_back(innerFormInfo);
        }
    }
    HILOG_DEBUG("SaveEntries end");
}

ErrCode FormInfoRdbStorageMgr::LoadFormData(std::vector<InnerFormInfo> &innerFormInfos)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    ErrCode result;
    std::unordered_map<std::string, std::string> value;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        result = rdbDataManager_->QueryData(FORM_ID_PREFIX, value);
    }
    if (result != ERR_OK) {
        HILOG_ERROR("get entries error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SaveEntries(value, innerFormInfos);
    
    HILOG_DEBUG("%{public}s end", __func__);
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::SaveStorageFormData(const InnerFormInfo &innerFormInfo)
{
    HILOG_DEBUG("%{public}s called, formId[%{public}" PRId64 "]", __func__, innerFormInfo.GetFormId());
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    std::string formId = std::to_string(innerFormInfo.GetFormId());
    std::string key = std::string().append(FORM_ID_PREFIX).append(formId);
    std::string value = innerFormInfo.ToString();
    ErrCode result;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        result = rdbDataManager_->InsertData(key, value);
    }
    if (result != ERR_OK) {
        HILOG_ERROR("put innerFormInfo to RdbStore error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::ModifyStorageFormData(const InnerFormInfo &innerFormInfo)
{
    HILOG_DEBUG("%{public}s called, formId[%{public}" PRId64 "]", __func__, innerFormInfo.GetFormId());
    std::string formId = std::to_string(innerFormInfo.GetFormId());
    ErrCode ret = DeleteStorageFormData(formId);
    if (ret == ERR_OK) {
        SaveStorageFormData(innerFormInfo);
    }

    return ret;
}

ErrCode FormInfoRdbStorageMgr::DeleteStorageFormData(const std::string &formId)
{
    HILOG_DEBUG("%{public}s called, formId[%{public}s]", __func__, formId.c_str());
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        if (!CheckRdbStore()) {
            HILOG_ERROR("RdbStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    std::string key = std::string().append(FORM_ID_PREFIX).append(formId);
    ErrCode result;
    {
        std::lock_guard<std::mutex> lock(rdbStorePtrMutex_);
        result = rdbDataManager_->DeleteData(key);
    }

    if (result != ERR_OK) {
        HILOG_ERROR("delete key error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_DEBUG("delete value to RdbStore success");
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
