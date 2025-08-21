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

#include "data_center/form_info/form_info_rdb_storage_mgr.h"

#include <cinttypes>
#include <thread>
#include <unistd.h>
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t MAX_TIMES = 600; // 600 * 100ms = 1min
constexpr int32_t SLEEP_INTERVAL = 100 * 1000; // 100ms
const std::string FORM_INFO_PREFIX = "formInfo_";
const std::string FORM_ID_PREFIX = "formId_";
const std::string STATUS_DATA_PREFIX = "statusData_";
const std::string FORM_VERSION_KEY = "versionCode_form";
constexpr char MULTI_APP_FORM_VERSION_PREFIX[] = "versionCode_multiAppForm_";
} // namespace

FormInfoRdbStorageMgr::FormInfoRdbStorageMgr()
{
    HILOG_DEBUG("FormInfoRdbStorageMgr is created");
    FormRdbTableConfig formRdbTableConfig;
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form info rdb storage mgr init form rdb table fail");
        FormEventReport::SendFormFailedEvent(FormEventName::INIT_FMS_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(InitFmsFailedErrorType::LOAD_FORM_DB_FAILED));
    }
}

FormInfoRdbStorageMgr::~FormInfoRdbStorageMgr()
{
    HILOG_DEBUG("FormInfoRdbStorageMgr is deleted");
}

ErrCode FormInfoRdbStorageMgr::LoadFormInfos(std::vector<std::pair<std::string, std::string>> &formInfoStorages)
{
    HILOG_DEBUG("FormInfoAllRdbStorageMgr load all form infos");
    std::unordered_map<std::string, std::string> value;
    ErrCode result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, FORM_INFO_PREFIX, value);
    if (result != ERR_OK) {
        HILOG_ERROR("get entries error");
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::LOAD_DATABASE_FAILED));
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
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("FormInfoRdbStorageMgr remove form info, bundleName=%{public}s", bundleName.c_str());

    std::string key = std::string().append(FORM_INFO_PREFIX).append(bundleName);
    ErrCode result = FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, key);
    if (result != ERR_OK) {
        HILOG_ERROR("remove formInfoStorages from rdbStore error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::UpdateBundleFormInfos(const std::string &bundleName, const std::string &formInfoStorages)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("FormInfoRdbStorageMgr update form info, bundleName=%{public}s", bundleName.c_str());
    std::string key = std::string().append(FORM_INFO_PREFIX).append(bundleName);
    std::string value = formInfoStorages;
    ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, key, value);
    if (result != ERR_OK) {
        HILOG_ERROR("update formInfoStorages to rdbStore error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

void FormInfoRdbStorageMgr::SaveEntries(
    const std::unordered_map<std::string, std::string> &value, std::vector<InnerFormInfo> &innerFormInfos)
{
    for (const auto &item : value) {
        InnerFormInfo innerFormInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(item.second, nullptr, false);
        if (jsonObject.is_discarded() || innerFormInfo.FromJson(jsonObject) != true) {
            HILOG_ERROR("error key: %{private}s", item.first.c_str());
            FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, item.first);
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
    HILOG_DEBUG("call");
    ErrCode result;
    std::unordered_map<std::string, std::string> value;
    result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, FORM_ID_PREFIX, value);
    if (result != ERR_OK) {
        HILOG_ERROR("get entries error");
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::LOAD_DATABASE_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SaveEntries(value, innerFormInfos);

    HILOG_DEBUG("end");
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::SaveStorageFormData(const InnerFormInfo &innerFormInfo)
{
    HILOG_DEBUG("formId[%{public}" PRId64 "]", innerFormInfo.GetFormId());
    std::string formId = std::to_string(innerFormInfo.GetFormId());
    std::string key = std::string().append(FORM_ID_PREFIX).append(formId);
    std::string value = innerFormInfo.ToString();
    ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, key, value);
    if (result != ERR_OK) {
        HILOG_ERROR("put innerFormInfo to RdbStore error");
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_SAVE_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::ModifyStorageFormData(const InnerFormInfo &innerFormInfo)
{
    HILOG_DEBUG("formId[%{public}" PRId64 "]", innerFormInfo.GetFormId());
    std::string formId = std::to_string(innerFormInfo.GetFormId());
    ErrCode ret = DeleteStorageFormData(formId);
    if (ret == ERR_OK) {
        SaveStorageFormData(innerFormInfo);
    }

    return ret;
}

ErrCode FormInfoRdbStorageMgr::DeleteStorageFormData(const std::string &formId)
{
    HILOG_DEBUG("formId[%{public}s]", formId.c_str());
    std::string key = std::string().append(FORM_ID_PREFIX).append(formId);
    ErrCode result = FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, key);
    if (result != ERR_OK) {
        HILOG_ERROR("delete key error");
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_DELETE_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    key = std::string().append(STATUS_DATA_PREFIX).append(formId);
    result = FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, key);
    if (result != ERR_OK) {
        HILOG_ERROR("delete status data of %{public}s failed", formId.c_str());
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_DELETE_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    HILOG_DEBUG("delete value to RdbStore success");
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::LoadStatusData(const std::string &formId, std::string &statusData)
{
    HILOG_DEBUG("formId is %{public}s", formId.c_str());
    if (formId.empty()) {
        HILOG_ERROR("empty formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    ErrCode result;
    std::string key = std::string().append(STATUS_DATA_PREFIX).append(formId);
    result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, key, statusData);
    if (result != ERR_OK) {
        HILOG_ERROR("load status data of %{public}s failed, code is %{public}d", formId.c_str(), result);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_QUERY_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::UpdateStatusData(const std::string &formId, const std::string &statusData)
{
    HILOG_DEBUG("formId is %{public}s", formId.c_str());
    if (formId.empty() || statusData.empty()) {
        HILOG_ERROR("empty formId or statusData");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    ErrCode result;
    std::string key = std::string().append(STATUS_DATA_PREFIX).append(formId);
    result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, key, statusData);
    if (result != ERR_OK) {
        HILOG_ERROR("update status data of %{public}s to rdbstore failed, code is %{public}d", formId.c_str(), result);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::GetFormVersionCode(std::string &versionCode)
{
    HILOG_INFO("call");
    ErrCode result = FormRdbDataMgr::GetInstance().QueryData(
        Constants::FORM_RDB_TABLE_NAME, FORM_VERSION_KEY, versionCode);
    if (result != ERR_OK) {
        HILOG_ERROR("get form version code failed, code is %{public}d", result);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::LOAD_DATABASE_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_INFO("get form version code success. versionCode:%{public}s", versionCode.c_str());
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::UpdateFormVersionCode()
{
    HILOG_INFO("call. versioncode:%{public}d", Constants::FORM_VERSION_CODE);
    ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, FORM_VERSION_KEY,
        std::to_string(Constants::FORM_VERSION_CODE));
    if (result != ERR_OK) {
        HILOG_ERROR("update form version code to rdbstore failed, code is %{public}d", result);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_SAVE_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::GetMultiAppFormVersionCode(const std::string &bundleName, std::string &versionCode)
{
    HILOG_INFO("call");
    std::string key = MULTI_APP_FORM_VERSION_PREFIX + bundleName;
    ErrCode result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, key, versionCode);
    if (result != ERR_OK) {
        HILOG_ERROR("get multi app form version code failed, code is %{public}d", result);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::LOAD_DATABASE_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_INFO("get multi app form version code success.");
    return ERR_OK;
}

ErrCode FormInfoRdbStorageMgr::UpdateMultiAppFormVersionCode(const std::string &bundleName,
    const std::string &versionCode)
{
    HILOG_INFO("call. bundleName: %{public}s", bundleName.c_str());
    std::string key = MULTI_APP_FORM_VERSION_PREFIX + bundleName;
    ErrCode result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, key, versionCode);
    if (result != ERR_OK) {
        HILOG_ERROR("update multi app form version code to rdbstore failed, code is %{public}d", result);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_SAVE_FORMID_FAILED));
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
