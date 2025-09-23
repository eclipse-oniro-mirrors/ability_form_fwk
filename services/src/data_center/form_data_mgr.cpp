/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "data_center/form_data_mgr.h"

#include <cinttypes>
#include <type_traits>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "data_center/form_cache_mgr.h"
#include "form_constants.h"
#include "data_center/form_basic_info_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "form_mgr_errors.h"
#include "form_observer/form_observer_record.h"
#include "form_provider/form_provider_mgr.h"
#include "data_center/form_record/form_record.h"
#include "form_render/form_render_mgr.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "form_xml_parser.h"
#include "ipc_skeleton.h"
#include "js_form_state_observer_interface.h"
#include "running_form_info.h"
#include "data_center/form_record/form_record_report.h"
#include "form_event_report.h"
#include "common/util/form_task_common.h"
#include "form_mgr/form_mgr_queue.h"
#include "status_mgr_center/form_status.h"
#include "parameter.h"
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr char MEMMORY_WATERMARK[] = "resourceschedule.memmgr.min.memmory.watermark";

static void OnMemoryWatermarkChange(const char *key, const char *value, [[maybe_unused]] void *context)
{
    HILOG_INFO("OnMemoryWatermarkChange, key: %{public}s, value: %{public}s", key, value);
    bool isLowMemory = (std::string(value) == "true");
    FormDataMgr::GetInstance().SetIsLowMemory(isLowMemory);
    if (!isLowMemory) {
        FormRenderMgr::GetInstance().RerenderAllFormsImmediate(FormUtil::GetCurrentAccountId());
    }
}
}

FormDataMgr::FormDataMgr()
{
    HILOG_INFO("create");
    InitLowMemoryStatus();
}
FormDataMgr::~FormDataMgr()
{
    HILOG_INFO("destroy");
}

/**
 * @brief Allot form info by item info.
 * @param formInfo Form item info.
 * @param callingUid The UID of the proxy.
 * @param userId User ID.
 * @return Returns form record.
 */
FormRecord FormDataMgr::AllotFormRecord(const FormItemInfo &formInfo, const int callingUid, const int32_t userId)
{
    HILOG_INFO("call formId: %{public}" PRId64 " userId: %{public}d callingUid: %{public}d",
        formInfo.GetFormId(), userId, callingUid);
    if (formInfo.IsTemporaryForm() && !ExistTempForm(formInfo.GetFormId())) {
        std::lock_guard<std::mutex> lock(formTempMutex_);
        tempForms_.emplace_back(formInfo.GetFormId());
    }
    FormRecord record;
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        if (formRecords_.empty()) { // formRecords_ is empty, create a new one
            HILOG_DEBUG("form info not exist");
            record = CreateFormRecord(formInfo, callingUid, userId);
            formRecords_.emplace(formInfo.GetFormId(), record);
        } else {
            auto info = formRecords_.find(formInfo.GetFormId());
            if (info == formRecords_.end()) {
                HILOG_DEBUG("form info not find");
                record = CreateFormRecord(formInfo, callingUid, userId);
                formRecords_.emplace(formInfo.GetFormId(), record);
            } else {
                record = info->second;
            }
        }
    }
    HILOG_INFO("end formId: %{public}" PRId64, formInfo.GetFormId());
    FormBasicInfo basic {
        record.formId, record.abilityName, record.bundleName, record.moduleName, record.formName, record.packageName
    };
    FormBasicInfoMgr::GetInstance().AddFormBasicInfo(basic);
    return record;
}
/**
 * @brief Delete form js info by form record.
 * @param formId The Id of the form.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::DeleteFormRecord(const int64_t formId)
{
    HILOG_INFO("delete record, form:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto iter = formRecords_.find(formId);
    if (iter == formRecords_.end()) {
        HILOG_ERROR("form record not exist");
        return false;
    }
    formRecords_.erase(iter);
    FormUtil::DeleteFormId(formId);
    FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(formId);
    return true;
}

/**
 * @brief Allot form host record by caller token.
 * @param info The form item info.
 * @param callerToken callerToken
 * @param formId The Id of the form.
 * @param callingUid The UID of the proxy.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::AllotFormHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const int64_t formId, const int callingUid)
{
    HILOG_INFO("call formId: %{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (callerToken == record.GetFormHostClient()) {
            if (record.GetFormsCount() == 0) {
                FormMgrQueue::GetInstance().CancelDelayTask(
                    std::make_pair((int64_t)TaskType::DELETE_FORM_HOST_RECORD, callingUid));
                HILOG_INFO("cancel delay task of recheck whether need clean form host");
            }
            record.AddForm(formId);
            HILOG_INFO("addForm");
            return true;
        }
    }
    FormHostRecord hostRecord;
    bool isCreated = CreateHostRecord(info, callerToken, callingUid, hostRecord);
    if (isCreated) {
        hostRecord.AddForm(formId);
        clientRecords_.emplace_back(hostRecord);
        HILOG_INFO("emplace");
        return true;
    }
    return false;
}
/**
 * @brief Create host record.
 * @param info The form item info.
 * @param callerToken The UID of the proxy.
 * @param callingUid The UID of the proxy.
 * @param record The form host record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::CreateHostRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const int callingUid, FormHostRecord& record)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("invalid param");
        return false;
    }

    record = FormHostRecord::CreateRecord(info, callerToken, callingUid);
    return true;
}

static void initFormRecord(FormRecord &newRecord, const FormItemInfo &formInfo)
{
    newRecord.formId = formInfo.GetFormId();
    newRecord.providerUserId = FormUtil::GetCurrentAccountId();
    newRecord.packageName = formInfo.GetPackageName();
    newRecord.bundleName = formInfo.GetProviderBundleName();
    newRecord.moduleName = formInfo.GetModuleName();
    newRecord.abilityName = formInfo.GetAbilityName();
    newRecord.formName = formInfo.GetFormName();
    newRecord.specification = formInfo.GetSpecificationId();
    newRecord.isEnableUpdate = formInfo.IsEnableUpdateFlag();
    newRecord.formTempFlag = formInfo.IsTemporaryForm();
    newRecord.formVisibleNotify = formInfo.IsFormVisibleNotify();
    newRecord.isDistributedForm = formInfo.IsDistributedForm();
    newRecord.uiModule = formInfo.GetUiModuleName();
    newRecord.jsFormCodePath =
        formInfo.GetHapSourceByModuleName(newRecord.isDistributedForm ? newRecord.uiModule : newRecord.moduleName);
    newRecord.formSrc = formInfo.GetFormSrc();
    newRecord.formWindow = formInfo.GetFormWindow();
    newRecord.versionName = formInfo.GetVersionName();
    newRecord.versionCode = formInfo.GetVersionCode();
    newRecord.compatibleVersion = formInfo.GetCompatibleVersion();
    newRecord.formVisibleNotifyState = 0;
    newRecord.type = formInfo.GetType();
    newRecord.uiSyntax = formInfo.GetUiSyntax();
    newRecord.isDynamic = formInfo.IsDynamic();
    newRecord.transparencyEnabled = formInfo.IsTransparencyEnabled();
    newRecord.privacyLevel = formInfo.GetPrivacyLevel();
    newRecord.isSystemApp = formInfo.GetSystemAppFlag();
    newRecord.description = formInfo.GetDescription();
    newRecord.formLocation = formInfo.GetFormLocation();
    newRecord.isThemeForm = formInfo.GetIsThemeForm();
    newRecord.enableForm = formInfo.IsEnableForm();
    newRecord.lockForm = formInfo.IsLockForm();
    newRecord.protectForm = formInfo.IsProtectForm();
}

/**
 * @brief Create form record.
 * @param formInfo The form item info.
 * @param callingUid The UID of the proxy.
 * @param userId User ID.
 * @return Form record.
 */
FormRecord FormDataMgr::CreateFormRecord(const FormItemInfo &formInfo, const int callingUid, const int32_t userId) const
{
    HILOG_INFO("create formId: %{public}" PRId64 " userId: %{public}d", formInfo.GetFormId(), userId);
    FormRecord newRecord;
    initFormRecord(newRecord, formInfo);
    newRecord.userId = userId;
    if (newRecord.isEnableUpdate) {
        ParseUpdateConfig(newRecord, formInfo);
    }
    if (std::find(newRecord.formUserUids.begin(), newRecord.formUserUids.end(),
        callingUid) == newRecord.formUserUids.end()) {
        newRecord.formUserUids.emplace_back(callingUid);
    }
    newRecord.isDataProxy = formInfo.GetDataProxyFlag();
    newRecord.uid = formInfo.GetProviderUid();
    newRecord.modulePkgNameMap = formInfo.GetModulePkgNameMap();
    newRecord.formBundleType = formInfo.GetFormBundleType();
    formInfo.GetHapSourceDirs(newRecord.hapSourceDirs);
    newRecord.renderingMode = formInfo.GetRenderingMode();
    newRecord.conditionUpdate = formInfo.GetConditionUpdate();
    newRecord.isDataProxyIgnoreFormVisible = formInfo.GetDataProxyIgnoreFormVisibility();
    HILOG_DEBUG("end");
    return newRecord;
}
/**
 * @brief Create form js info by form record.
 * @param formId The Id of the form.
 * @param record Form record.
 * @param formInfo Js form info.
 */
void FormDataMgr::CreateFormJsInfo(const int64_t formId, const FormRecord &record, FormJsInfo &formInfo)
{
    formInfo.formId = formId;
    formInfo.bundleName = record.bundleName;
    formInfo.abilityName = record.abilityName;
    formInfo.formName = record.formName;
    formInfo.moduleName = record.isDistributedForm ? record.uiModule : record.moduleName;
    formInfo.formTempFlag = record.formTempFlag;
    formInfo.jsFormCodePath = record.jsFormCodePath;
    formInfo.formSrc = record.formSrc;
    formInfo.formWindow = record.formWindow;
    formInfo.versionCode = record.versionCode;
    formInfo.versionName = record.versionName;
    formInfo.compatibleVersion = record.compatibleVersion;
    formInfo.type = record.type;
    formInfo.uiSyntax = record.uiSyntax;
    formInfo.isDynamic = record.isDynamic;
    formInfo.transparencyEnabled = record.transparencyEnabled;
    formInfo.modulePkgNameMap = record.modulePkgNameMap;
    formInfo.formData = record.formProviderInfo.GetFormDataString();
    formInfo.formProviderData = record.formProviderInfo.GetFormData();
}

void FormDataMgr::SetConfigMap(const std::map<std::string, int32_t> &configMap)
{
    std::lock_guard<std::mutex> lock(formConfigMapMutex_);
    formConfigMap_ = configMap;
}

void FormDataMgr::GetConfigParamFormMap(const std::string &key, int32_t &value) const
{
    std::lock_guard<std::mutex> lock(formConfigMapMutex_);
    if (formConfigMap_.empty()) {
        HILOG_ERROR("empty configMap");
        return;
    }
    auto iter = formConfigMap_.find(key);
    if (iter == formConfigMap_.end()) {
        HILOG_ERROR("no corresponding value found, use the default value");
        return;
    }
    value = iter->second;
    HILOG_INFO("key:%{public}s, value:%{public}d", key.c_str(), value);
}

void FormDataMgr::RecycleAllRecyclableForms() const
{
    HILOG_INFO("start");
    std::vector<int64_t> formIds;
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        for (auto itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
            if (itFormRecord->second.lowMemoryRecycleStatus == LowMemoryRecycleStatus::RECYCLABLE) {
                formIds.emplace_back(itFormRecord->first);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(formHostRecordMutex_);
        for (auto itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
            std::vector<int64_t> matchedFormIds;
            for (const int64_t &formId : formIds) {
                if (itHostRecord->Contains(formId)) {
                    matchedFormIds.emplace_back(formId);
                }
            }
            if (!matchedFormIds.empty()) {
                Want want;
                itHostRecord->OnRecycleForms(matchedFormIds, want);
            }
        }
    }
}

void FormDataMgr::RecycleForms(const std::vector<int64_t> &formIds, const int &callingUid, const Want &want) const
{
    HILOG_INFO("start callingUid:%{public}d", callingUid);
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        if (itHostRecord->GetCallerUid() != callingUid) {
            continue;
        }
        std::vector<int64_t> matchedFormIds;
        for (const int64_t &formId : formIds) {
            if (itHostRecord->Contains(formId)) {
                matchedFormIds.emplace_back(formId);
            }
        }
        if (!matchedFormIds.empty()) {
            itHostRecord->OnRecycleForms(matchedFormIds, want);
        }
        break;
    }
}

/**
 * @brief Check temp form count is max.
 * @return Returns ERR_OK if the temp form not reached; returns ERR_MAX_SYSTEM_TEMP_FORMS is reached.
 */
int FormDataMgr::CheckTempEnoughForm() const
{
    int32_t maxTempSize = Constants::MAX_TEMP_FORMS;
    GetConfigParamFormMap(Constants::MAX_TEMP_FORM_SIZE, maxTempSize);
    maxTempSize = ((maxTempSize > Constants::MAX_TEMP_FORMS) || (maxTempSize < 0)) ?
        Constants::MAX_TEMP_FORMS : maxTempSize;
    HILOG_DEBUG("maxTempSize:%{public}d", maxTempSize);

    if (GetTempFormCount() >= maxTempSize) {
        HILOG_WARN("already exist %{public}d temp forms in system", maxTempSize);
        FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED, 0, "", "",
            static_cast<int32_t>(AddFormFailedErrorType::NUMBER_EXCEEDING_LIMIT),
            ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS);
        return ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS;
    }
    return ERR_OK;
}

/**
 * @brief Check form count is max.
 * @param callingUid The UID of the proxy.
 * @param currentUserId The current userId.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
int FormDataMgr::CheckEnoughForm(const int callingUid, const int32_t currentUserId) const
{
    HILOG_INFO("callingUid:%{public}d, currentUserId:%{public}d", callingUid, currentUserId);

    int32_t maxFormsSize = Constants::MAX_FORMS;
    GetConfigParamFormMap(Constants::MAX_NORMAL_FORM_SIZE, maxFormsSize);
    maxFormsSize = ((maxFormsSize > Constants::MAX_FORMS) || (maxFormsSize < 0)) ?
        Constants::MAX_FORMS : maxFormsSize;
    HILOG_DEBUG("maxFormsSize:%{public}d", maxFormsSize);

    int32_t maxRecordPerApp = Constants::MAX_RECORD_PER_APP;
    GetConfigParamFormMap(Constants::HOST_MAX_FORM_SIZE, maxRecordPerApp);
    maxRecordPerApp = ((maxRecordPerApp > Constants::MAX_RECORD_PER_APP) || (maxRecordPerApp < 0)) ?
        Constants::MAX_RECORD_PER_APP : maxRecordPerApp;
    HILOG_DEBUG("maxRecordPerApp:%{public}d", maxRecordPerApp);

    if (maxRecordPerApp == 0) {
        HILOG_ERROR("The maximum number of normal cards in pre host is 0");
        return ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT;
    }

    const auto formDbInfoSize = FormDbCache::GetInstance().GetAllFormInfoSize();
    HILOG_INFO("already use %{public}d forms by userId", formDbInfoSize);
    if (formDbInfoSize >= maxFormsSize) {
        std::vector<FormDBInfo> formDBInfos;
        FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
        std::map<Constants::FormLocation, int> locationMap;
        for (const auto& dbInfo : formDBInfos) {
            if (locationMap.count(dbInfo.formLocation) == 0) {
                locationMap[dbInfo.formLocation] = 1;
            } else {
                locationMap[dbInfo.formLocation] = locationMap[dbInfo.formLocation] + 1;
            }
        }
        Constants::FormLocation maxLocation = Constants::FormLocation::OTHER;
        int maxCount = 0;
        for (auto &location : locationMap) {
            HILOG_WARN("location:%{public}hhd-count:%{public}d", location.first, location.second);
            if (location.second > maxCount) {
                maxCount = location.second;
                maxLocation = location.first;
            }
        }
        HILOG_WARN("exceeds max form number %{public}d, maxLocation:%{public}hhd-maxCount:%{public}d",
            maxFormsSize, maxLocation, maxCount);
        FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED, 0, "", "",
            static_cast<int32_t>(AddFormFailedErrorType::NUMBER_EXCEEDING_LIMIT),
            ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS);
        return ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS;
    }

    int32_t currentAccountId = FormUtil::GetCurrentAccountId();
    int callingUidFormCounts = FormDbCache::GetInstance().GetFormCountsByCallingUid(currentAccountId, callingUid);
    if (callingUidFormCounts >= maxRecordPerApp) {
        HILOG_WARN("already use %{public}d forms by userId==currentAccountId", maxRecordPerApp);
        return ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT;
    }

    return ERR_OK;
}

/**
 * @brief Delete temp form.
 * @param formId The Id of the form.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::DeleteTempForm(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formTempMutex_);
    auto iter = std::find(tempForms_.begin(), tempForms_.end(), formId);
    if (iter == tempForms_.end()) {
        HILOG_ERROR("not find tempForm:%{public}" PRId64, formId);
        return false;
    }
    tempForms_.erase(iter);
    return true;
}
/**
 * @brief Check temp form is exist.
 * @param formId The Id of the form.
 * @return Returns true if the temp form is exist; returns false is not exist.
 */
bool FormDataMgr::ExistTempForm(const int64_t formId) const
{
    std::lock_guard<std::mutex> lock(formTempMutex_);
    return (std::find(tempForms_.begin(), tempForms_.end(), formId) != tempForms_.end());
}
/**
 * @brief Check calling uid is valid.
 * @param formUserUids The form user uids.
 * @return Returns true if this user uid is valid; returns false otherwise.
 */
bool FormDataMgr::IsCallingUidValid(const std::vector<int> &formUserUids) const
{
    if (formUserUids.empty()) {
        HILOG_ERROR("empty formUserUids");
        return false;
    }
    for (const auto &userUid : formUserUids) {
        if (userUid == IPCSkeleton::GetCallingUid()) {
            return true;
        }
    }
    HILOG_ERROR("not find valid uid");
    return false;
}
/**
 * @brief Modify form temp flag by formId.
 * @param formId The Id of the form.
 * @param formTempFlag The form temp flag.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::ModifyFormTempFlag(const int64_t formId, const bool formTempFlag)
{
    HILOG_INFO("modify form temp flag by formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    if (!(formRecords_.count(formId) > 0)) {
        HILOG_ERROR("formInfo not exist");
        return false;
    }
    formRecords_[formId].formTempFlag = formTempFlag;
    return true;
}
/**
 * @brief Add form user uid from form record.
 * @param formId The Id of the form.
 * @param formRecord The form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::AddFormUserUid(const int64_t formId, const int formUserUid)
{
    HILOG_INFO("add form user uid by formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    if (!(formRecords_.count(formId) > 0)) {
        HILOG_ERROR("formInfo not exist");
        return false;
    }
    if (std::find(formRecords_[formId].formUserUids.begin(), formRecords_[formId].formUserUids.end(),
        formUserUid) == formRecords_[formId].formUserUids.end()) {
        formRecords_[formId].formUserUids.emplace_back(formUserUid);
    }
    return true;
}
/**
 * @brief Delete form user uid from form record.
 * @param formId The Id of the form.
 * @param uid calling user id.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::DeleteFormUserUid(const int64_t formId, const int uid)
{
    HILOG_INFO("formId:%{public}" PRId64 ", uid:%{public}d", formId, uid);
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    if (formRecords_.count(formId) > 0) {
        auto iter = std::find(formRecords_.at(formId).formUserUids.begin(),
            formRecords_.at(formId).formUserUids.end(), uid);
        if (iter != formRecords_.at(formId).formUserUids.end()) {
            formRecords_.at(formId).formUserUids.erase(iter);
        }
        return true;
    } else {
        HILOG_ERROR("formInfo not find");
        return false;
    }
}
/**
 * @brief Update form record.
 * @param formId The Id of the form.
 * @param formRecord The form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::UpdateFormRecord(const int64_t formId, const FormRecord &formRecord)
{
    HILOG_DEBUG("get form record by formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info != formRecords_.end()) {
        formRecords_[formId] = formRecord;
        return true;
    }
    return false;
}
/**
 * @brief Get form record.
 * @param formId The Id of the form.
 * @param formRecord The form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    HILOG_DEBUG("get form record by formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info == formRecords_.end()) {
        HILOG_ERROR("formInfo not find");
        return false;
    }
    formRecord = info->second;

    HILOG_DEBUG("get form record successfully");
    return true;
}
/**
 * @brief Get form record.
 * @param bundleName Bundle name.
 * @param formInfos The form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::GetFormRecord(const std::string &bundleName, std::vector<FormRecord> &formInfos, int32_t userId) const
{
    HILOG_DEBUG("get form record by bundleName");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (bundleName == itFormRecord->second.bundleName &&
            (userId == Constants::INVALID_USER_ID || userId == itFormRecord->second.userId)) {
            formInfos.emplace_back(itFormRecord->second);
        }
    }
    if (formInfos.size() > 0) {
        return true;
    } else {
        HILOG_DEBUG("formInfo not find");
        return false;
    }
}

/**
 * @brief Get form record.
 * @param formId The Id of the form.
 * @param formRecord The form record.
 * @return Set true if DataProxy Update.
 */
void FormDataMgr::SetDataProxyUpdate(const int64_t formId)
{
    HILOG_DEBUG("get form record by formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info != formRecords_.end()) {
        info->second.isDataProxyUpdate = true;
    }
}

/**
 * @brief DataProxy update ignore visibility check.
 * @param formRecord The form record.
 * @return return true if DataProxy Update.
 */
bool FormDataMgr::IsDataProxyIgnoreFormVisibility(const int64_t formId) const
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info != formRecords_.end()) {
        return info->second.isDataProxyUpdate && info->second.isDataProxyIgnoreFormVisible;
    }
    return false;
}


/**
 * @brief Set dataProxy update flage default.
 * @param formRecord The form record.
 */
void FormDataMgr::ResetDataProxyUpdate (const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info != formRecords_.end()) {
        info->second.isDataProxyUpdate = false;
    }
}

/**
 * @brief Get published form record by formId.
 * @param bundleName Bundle name.
 * @param formInfo The form record.
 * @param formId The Id of the form.
 * @param userId User ID.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDataMgr::GetPublishedFormInfoById(const std::string &bundleName, RunningFormInfo &formInfo,
    const int64_t &formId, int32_t userId) const
{
    HILOG_DEBUG("get form record by bundleName & formId");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (bundleName == itFormRecord->second.bundleName && formId == itFormRecord->second.formId &&
            (userId == Constants::INVALID_USER_ID || userId == itFormRecord->second.userId)) {
            formInfo.formId = itFormRecord->second.formId;
            FillBasicRunningFormInfoByFormRecord(itFormRecord->second, formInfo);
            HILOG_DEBUG("GetPublishedFormInfoById success, formId:%{public}" PRId64, formId);
            return ERR_OK;
        }
    }
    HILOG_DEBUG("formInfo not find");
    return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
}

/**
 * @brief Get published form records.
 * @param bundleName Bundle name.
 * @param formInfos The form record list.
 * @param userId User ID.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDataMgr::GetPublishedFormInfos(const std::string &bundleName, std::vector<RunningFormInfo> &formInfos,
    int32_t userId) const
{
    HILOG_DEBUG("get form record by bundleName");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (bundleName == itFormRecord->second.bundleName &&
            (userId == Constants::INVALID_USER_ID || userId == itFormRecord->second.userId)) {
            RunningFormInfo formInfo;
            formInfo.formId = itFormRecord->second.formId;
            FillBasicRunningFormInfoByFormRecord(itFormRecord->second, formInfo);
            formInfos.emplace_back(formInfo);
        }
    }
    if (formInfos.size() > 0) {
        HILOG_DEBUG("GetPublishedFormInfos success, size:%{public}zu", formInfos.size());
        return ERR_OK;
    } else {
        HILOG_DEBUG("formInfo not find");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
}

/**
 * @brief Get form record.
 * @param conditionType condition Type.
 * @param formInfos The form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::GetFormRecordByCondition(int32_t conditionType, std::vector<FormRecord> &formInfos) const
{
    HILOG_DEBUG("get form record by conditionType");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        std::vector<int32_t> conditionUpdate = itFormRecord->second.conditionUpdate;
        for (int32_t item : conditionUpdate) {
            if (item == conditionType) {
                formInfos.emplace_back(itFormRecord->second);
                break;
            }
        }
    }
    if (formInfos.size() > 0) {
        return true;
    } else {
        HILOG_DEBUG("formInfo not find");
        return false;
    }
}

/**
 * @brief Get temporary form record.
 * @param formTempRecords The temp form record.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::GetTempFormRecord(std::vector<FormRecord> &formTempRecords)
{
    HILOG_INFO("Get temporary form record");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (itFormRecord->second.formTempFlag) {
            formTempRecords.emplace_back(itFormRecord->second);
        }
    }
    if (!formTempRecords.empty()) {
        return true;
    } else {
        HILOG_INFO("The count of temporary form is zero");
        return false;
    }
}
/**
 * @brief Check form record is exist.
 * @param formId The Id of the form.
 * @return Returns true if the form record is exist; returns false is not exist.
 */
bool FormDataMgr::ExistFormRecord(const int64_t formId) const
{
    HILOG_INFO("check form record is exist");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    return (formRecords_.count(formId) > 0);
}
/**
 * @brief Has form user uids in form record.
 * @param formId The Id of the form.
 * @return Returns true if this form has form user uids; returns false is not has.
 */
bool FormDataMgr::HasFormUserUids(const int64_t formId) const
{
    HILOG_INFO("check form has user uids");
    FormRecord record;
    if (GetFormRecord(formId, record)) {
        return record.formUserUids.empty() ? false : true;
    }
    return false;
}
/**
 * @brief Get form host record.
 * @param formId The id of the form.
 * @param formHostRecord The form host record.
 */
void FormDataMgr::GetFormHostRecord(const int64_t formId, std::vector<FormHostRecord> &formHostRecords) const
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (record.Contains(formId)) {
            formHostRecords.emplace_back(record);
        }
    }
    HILOG_DEBUG("get form host record by formId, size is %{public}zu", formHostRecords.size());
}
void FormDataMgr::GetFormHostRemoteObj(const int64_t formId, std::vector<sptr<IRemoteObject>> &formHostObjs) const
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (record.Contains(formId)) {
            formHostObjs.emplace_back(record.GetFormHostClient());
        }
    }
    if (formHostObjs.empty()) {
        HILOG_WARN("empty formHostObjs");
        return;
    }
    HILOG_DEBUG("Get form host remote object by formId, size is %{public}zu", formHostObjs.size());
}
/**
 * @brief Delete form host record.
 * @param callerToken The client stub of the form host record.
 * @param formId The id of the form.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::DeleteHostRecord(const sptr<IRemoteObject> &callerToken, const int64_t formId)
{
    HILOG_WARN("form: %{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator iter;
    for (iter = clientRecords_.begin(); iter != clientRecords_.end(); ++iter) {
        if (callerToken == iter->GetFormHostClient()) {
            iter->DelForm(formId);
            if (iter->IsEmpty()) {
                HILOG_INFO("post delay recheck whether need clean form host task");
                PostDelayRecheckWhetherNeedCleanFormHostTask(iter->GetCallerUid(), callerToken);
            }
            break;
        }
    }
    return true;
}
/**
 * @brief Recheck whether need clean form host.
 * @param callerToken The client stub of the form host record.
 */
bool FormDataMgr::RecheckWhetherNeedCleanFormHost(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator iter;
    for (iter = clientRecords_.begin(); iter != clientRecords_.end(); ++iter) {
        if (callerToken == iter->GetFormHostClient()) {
            if (iter->IsEmpty()) {
                HILOG_WARN("clientRecords_ is empty, clean form host");
                iter->CleanResource();
                iter = clientRecords_.erase(iter);
                FormRenderMgr::GetInstance().CleanFormHost(callerToken, iter->GetCallerUid());
                return true;
            }
            break;
        }
    }
    HILOG_INFO("no need to clean form host");
    return false;
}
/**
 * @brief Clean removed forms form host.
 * @param removedFormIds The id list of the forms.
 */
void FormDataMgr::CleanHostRemovedForms(const std::vector<int64_t> &removedFormIds)
{
    HILOG_INFO("delete form host record by formId list");
    std::vector<int64_t> matchedIds;
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        for (const int64_t& formId : removedFormIds) {
            if (itHostRecord->Contains(formId)) {
                matchedIds.emplace_back(formId);
                itHostRecord->DelForm(formId);
            }
        }
        if (!matchedIds.empty()) {
            HILOG_INFO("OnFormUninstalled");
            itHostRecord->OnFormUninstalled(matchedIds);
        }
    }

    HILOG_INFO("end");
}

void FormDataMgr::UpdateHostForms(const std::vector<int64_t> &updateFormIds)
{
    HILOG_INFO("update form host record by formId list");
    std::vector<int64_t> matchedIds;
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (FormHostRecord &record : clientRecords_) {
        for (const int64_t &formId : updateFormIds) {
            if (record.Contains(formId)) {
                matchedIds.emplace_back(formId);
            }
        }
        if (!matchedIds.empty()) {
            HILOG_INFO("OnFormUninstalled");
            record.OnFormUninstalled(matchedIds);
            matchedIds.clear();
        }
    }
    HILOG_INFO("end");
}

/**
 * @brief Handle form host died.
 * @param remoteHost Form host proxy object.
 */
void FormDataMgr::HandleHostDied(const sptr<IRemoteObject> &remoteHost)
{
    std::vector<int64_t> recordTempForms;
    int remoteHostCallerUid = 0;
    {
        std::lock_guard<std::mutex> lock(formHostRecordMutex_);
        std::vector<FormHostRecord>::iterator itHostRecord;
        for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end();) {
            if (remoteHost == itHostRecord->GetFormHostClient()) {
                HandleHostDiedForTempForms(*itHostRecord, recordTempForms);
                HILOG_INFO("find died client,remove it");
                itHostRecord->CleanResource();
                remoteHostCallerUid = itHostRecord->GetCallerUid();
                itHostRecord = clientRecords_.erase(itHostRecord);
                break;
            } else {
                itHostRecord++;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        std::map<int64_t, FormRecord>::iterator itFormRecord;
        for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end();) {
            int64_t formId = itFormRecord->first;
            // if temp form, remove it
            if (std::find(recordTempForms.begin(), recordTempForms.end(), formId) != recordTempForms.end()) {
                FormRecord formRecord = itFormRecord->second;
                itFormRecord = formRecords_.erase(itFormRecord);
                FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(formId);
                FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, formRecord);
                FormDataProxyMgr::GetInstance().UnsubscribeFormData(formId);
            } else {
                itFormRecord++;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(formStateRecordMutex_);
        std::map<std::string, FormHostRecord>::iterator itFormStateRecord;
        for (itFormStateRecord = formStateRecord_.begin(); itFormStateRecord != formStateRecord_.end();) {
            if (remoteHost == itFormStateRecord->second.GetFormHostClient()) {
                HILOG_INFO("find died client, remove it from formStateRecord_");
                itFormStateRecord->second.CleanResource();
                itFormStateRecord = formStateRecord_.erase(itFormStateRecord);
                break;
            } else {
                itFormStateRecord++;
            }
        }
    }
    FormRenderMgr::GetInstance().CleanFormHost(remoteHost, remoteHostCallerUid);
}

/**
 * @brief Get the temp forms from host and delete temp form in cache.
 * @param record The form record.
 * @param recordTempForms gotten the temp forms.
 */
void FormDataMgr::HandleHostDiedForTempForms(const FormHostRecord &record, std::vector<int64_t> &recordTempForms)
{
    std::lock_guard<std::mutex> lock(formTempMutex_);
    std::vector<int64_t>::iterator itForm;
    for (itForm = tempForms_.begin(); itForm != tempForms_.end();) {
        if (record.Contains(*itForm)) {
            recordTempForms.emplace_back(*itForm);
            itForm = tempForms_.erase(itForm);
        } else {
            itForm++;
        }
    }
}

/**
 * @brief Refresh enable or not.
 * @param formId The Id of the form.
 * @return true on enable, false on disable.
 */
bool FormDataMgr::IsEnableRefresh(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (record.IsEnableRefresh(formId)) {
            return true;
        }
    }

    return false;
}

/**
 * @brief update enable or not.
 * @param formId The Id of the form.
 * @return true on enable, false on disable.
 */
bool FormDataMgr::IsEnableUpdate(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (record.IsEnableUpdate(formId)) {
            return true;
        }
    }
    return false;
}

int64_t FormDataMgr::PaddingUdidHash(const int64_t formId)
{
    if (!GenerateUdidHash()) {
        return -1;
    }
    // Compatible with int form id.
    uint64_t unsignedFormId = static_cast<uint64_t>(formId);
    if ((unsignedFormId & 0xffffffff00000000L) == 0) {
        uint64_t unsignedUdidHash  = static_cast<uint64_t>(udidHash_);
        uint64_t unsignedUdidHashFormId = unsignedUdidHash | unsignedFormId;
        int64_t udidHashFormId = static_cast<int64_t>(unsignedUdidHashFormId);
        return udidHashFormId;
    }
    return formId;
}

/**
 * @brief Generate form id.
 * @return form id.
 */
int64_t FormDataMgr::GenerateFormId()
{
    // generate by udidHash_
    if (!GenerateUdidHash()) {
        HILOG_ERROR("generateFormId no invalid udidHash_");
        return -1;
    }
    return FormUtil::GenerateFormId(udidHash_);
}
/**
 * @brief Generate udid.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::GenerateUdidHash()
{
    if (udidHash_ != Constants::INVALID_UDID_HASH) {
        return true;
    }

    bool genUdid = FormUtil::GenerateUdidHash(udidHash_);
    if (!genUdid) {
        HILOG_ERROR("fail generate udid");
        return false;
    }

    return true;
}
/**
 * @brief Get udid.
 * @return udid.
 */
int64_t FormDataMgr::GetUdidHash() const
{
    return udidHash_;
}
/**
 * @brief Set udid.
 * @param udidHash udid.
 */
void FormDataMgr::SetUdidHash(const int64_t udidHash)
{
    udidHash_ = udidHash;
}

/**
 * @brief Get the matched form host record by client stub.
 *
 * @param callerToken The client stub of the form host record.
 * @param formHostRecord The form host record.
 * @return Returns true if this function is successfully called, returns false otherwise.
 */
bool FormDataMgr::GetMatchedHostClient(const sptr<IRemoteObject> &callerToken, FormHostRecord &formHostRecord) const
{
    HILOG_DEBUG("get the matched form host record by client stub");
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (const FormHostRecord &record : clientRecords_) {
        if (callerToken == record.GetFormHostClient()) {
            formHostRecord = record;
            return true;
        }
    }

    HILOG_ERROR("form host record not find");
    return false;
}

/**
 * @brief Set needRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param needRefresh true or false.
 */
void FormDataMgr::SetNeedRefresh(const int64_t formId, const bool needRefresh)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.needRefresh = needRefresh;
}

/**
 * @brief Set needRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param needRefresh true or false.
 */
void FormDataMgr::SetRefreshType(const int64_t formId, const int refreshType)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.refreshType = refreshType;
}

/**
 * @brief get needRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param needRefresh true or false.
 */
void FormDataMgr::GetRefreshType(const int64_t formId, int &refreshType)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    refreshType = itFormRecord->second.refreshType;
}

/**
 * @brief Set needRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param needRefresh true or false.
 */
void FormDataMgr::SetNeedAddForm(const int64_t formId, const bool needAddForm)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.needAddForm = needAddForm;
}

/**
 * @brief Set isCountTimerRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param countTimerRefresh true or false.
 */
void FormDataMgr::SetCountTimerRefresh(const int64_t formId, const bool countTimerRefresh)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.isCountTimerRefresh = countTimerRefresh;
}

/**
 * @brief Set isTimerRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param timerRefresh true or false.
 */
void FormDataMgr::SetTimerRefresh(const int64_t formId, const bool timerRefresh)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.isTimerRefresh = timerRefresh;
}

/**
 * @brief Set isHostRefresh for FormRecord.
 * @param formId The Id of the form.
 * @param hostRefresh true or false.
 */
void FormDataMgr::SetHostRefresh(const int64_t formId, const bool hostRefresh)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find, form:%{public}" PRId64, formId);
        return;
    }
    itFormRecord->second.isHostRefresh = hostRefresh;
}

/**
 * @brief Clear want cache for FormRecord.
 * @param formId The Id of the form.
 */
void FormDataMgr::ClearWantCache(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find, form:%{public}" PRId64, formId);
        return;
    }
    itFormRecord->second.wantCacheMap.clear();
}

/**
 * @brief Clear host refresh flag.
 * @param formId The Id of the form.
 */
void FormDataMgr::ClearHostRefreshFlag(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find, form:%{public}" PRId64, formId);
        return;
    }
    if (itFormRecord->second.isHostRefresh) {
        HILOG_INFO("clean host refresh flag, form:%{public}" PRId64, formId);
        itFormRecord->second.isHostRefresh = false;
        itFormRecord->second.wantCacheMap.clear();
    }
}

/**
 * @brief Get updated form.
 * @param record FormRecord.
 * @param targetForms Target forms.
 * @param updatedForm Updated formnfo.
 * @return Returns true on success, false on failure.
 */
bool FormDataMgr::GetUpdatedForm(const FormRecord &record, const std::vector<FormInfo> &targetForms,
    FormInfo &updatedForm)
{
    if (targetForms.empty()) {
        HILOG_ERROR("empty targetForms");
        return false;
    }

    for (const FormInfo &item : targetForms) {
        if (IsSameForm(record, item)) {
            updatedForm = item;
            HILOG_DEBUG("find matched form");
            return true;
        }
    }
    return false;
}
/**
 * @brief Set isEnableUpdate for FormRecord.
 * @param formId The Id of the form.
 * @param enableUpdate true or false.
 */
void FormDataMgr::SetEnableUpdate(const int64_t formId, const bool enableUpdate)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.isEnableUpdate = enableUpdate;
}
/**
 * @brief Set update info for FormRecord.
 * @param formId The Id of the form.
 * @param enableUpdate true or false.
 * @param updateDuration Update duration.
 * @param updateAtHour Update at hour.
 * @param updateAtMin Update at minute.
 */
void FormDataMgr::SetUpdateInfo(
    const int64_t formId,
    const bool enableUpdate,
    const long updateDuration,
    const int updateAtHour,
    const int updateAtMin,
    const std::vector<std::vector<int>> updateAtTimes)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }

    itFormRecord->second.isEnableUpdate = enableUpdate;
    itFormRecord->second.updateDuration = updateDuration;
    itFormRecord->second.updateAtHour = updateAtHour;
    itFormRecord->second.updateAtMin = updateAtMin;
    itFormRecord->second.updateAtTimes = updateAtTimes;
}
/**
 * @brief Check if two forms is same or not.
 * @param record FormRecord.
 * @param formInfo FormInfo.
 * @return Returns true on success, false on failure.
 */
bool FormDataMgr::IsSameForm(const FormRecord &record, const FormInfo &formInfo)
{
    if (record.bundleName == formInfo.bundleName
        && record.moduleName == formInfo.moduleName
        && record.abilityName == formInfo.abilityName
        && record.formName == formInfo.name
        && std::find(formInfo.supportDimensions.begin(), formInfo.supportDimensions.end(), record.specification)
        != formInfo.supportDimensions.end()) {
        return true;
    }

    return false;
}
/**
 * @brief Clean removed form records.
 * @param removedForms The id list of the forms.
 */
void FormDataMgr::CleanRemovedFormRecords(const std::string &bundleName, std::set<int64_t> &removedForms)
{
    HILOG_INFO("clean removed form records");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end();) {
        auto itForm = std::find(removedForms.begin(), removedForms.end(), itFormRecord->first);
        if (itForm != removedForms.end()) {
            FormCacheMgr::GetInstance().DeleteData(itFormRecord->first);
            FormRenderMgr::GetInstance().StopRenderingForm(itFormRecord->first, itFormRecord->second);
            itFormRecord = formRecords_.erase(itFormRecord);
            FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(itFormRecord->first);
        } else {
            itFormRecord++;
        }
    }
}
/**
 * @brief Clean removed temp form records.
 * @param  bundleName BundleName.
 * @param removedForms The id list of the forms.
 */
void FormDataMgr::CleanRemovedTempFormRecords(const std::string &bundleName, const int32_t userId,
    std::set<int64_t> &removedForms)
{
    HILOG_INFO("clean removed form records");
    std::set<int64_t> removedTempForms;
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        std::map<int64_t, FormRecord>::iterator itFormRecord;
        for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end();) {
            if ((itFormRecord->second.formTempFlag) && (bundleName == itFormRecord->second.bundleName)
                && (userId == itFormRecord->second.providerUserId)) {
                removedTempForms.emplace(itFormRecord->second.formId);
                FormRenderMgr::GetInstance().StopRenderingForm(itFormRecord->first, itFormRecord->second);
                itFormRecord = formRecords_.erase(itFormRecord);
                FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(itFormRecord->first);
            } else {
                itFormRecord++;
            }
        }
    }

    if (removedTempForms.size() > 0) {
        std::lock_guard<std::mutex> lock(formTempMutex_);
        std::vector<int64_t>::iterator itTemp;
        for (itTemp = tempForms_.begin(); itTemp != tempForms_.end();) {
            if (removedTempForms.find(*itTemp) != removedTempForms.end()) {
                itTemp = tempForms_.erase(itTemp);
            } else {
                itTemp++;
            }
        }
        removedForms.merge(removedTempForms);
    }
}
/**
 * @brief Get recreate form records.
 * @param reCreateForms The id list of the forms.
 */
void FormDataMgr::GetReCreateFormRecordsByBundleName(const std::string &bundleName, std::set<int64_t> &reCreateForms)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (bundleName == itFormRecord->second.bundleName) {
            reCreateForms.emplace(itFormRecord->second.formId);
        }
    }
}
/**
 * @brief Set form isInited flag.
 * @param formId The Id of the form.
 * @param isInited isInited property
 */
void FormDataMgr::SetFormCacheInited(const int64_t formId, bool isInited)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.isInited = isInited;
    itFormRecord->second.needRefresh = !isInited;
}
/**
 * @brief Set versionUpgrade.
 * @param formId The Id of the form.
 * @param versionUpgrade true or false
 */
void FormDataMgr::SetVersionUpgrade(const int64_t formId, const bool versionUpgrade)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return;
    }
    itFormRecord->second.versionUpgrade = versionUpgrade;
}
/**
 * @brief Update form for host clients.
 * @param formId The Id of the form.
 * @param needRefresh true or false
 */
void FormDataMgr::UpdateHostNeedRefresh(const int64_t formId, const bool needRefresh)
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        if (itHostRecord->Contains(formId)) {
            itHostRecord->SetNeedRefresh(formId, needRefresh);
        }
    }
}

/**
 * @brief Update form for host clients.
 * @param formId The Id of the form.
 * @param formRecord The form info.
 * @return Returns true if form update, false if other.
 */
bool FormDataMgr::UpdateHostForm(const int64_t formId, const FormRecord &formRecord)
{
    bool isUpdated = false;
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        bool enableRefresh = formRecord.isVisible || itHostRecord->IsEnableUpdate(formId) ||
                             itHostRecord->IsEnableRefresh(formId);
        HILOG_INFO("formId:%{public}" PRId64 " enableRefresh:%{public}d", formId, enableRefresh);
        if (enableRefresh) {
            // update form
            itHostRecord->OnUpdate(formId, formRecord);
            // set needRefresh
            itHostRecord->SetNeedRefresh(formId, false);
            isUpdated = true;
        }
    }
    return isUpdated;
}

ErrCode FormDataMgr::HandleUpdateHostFormFlag(const std::vector<int64_t> &formIds, bool flag, bool isOnlyEnableUpdate,
                                              FormHostRecord &formHostRecord, std::vector<int64_t> &refreshForms)
{
    for (const int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("formId %{public}" PRId64 " less than 0", formId);
            continue;
        }

        int64_t matchedFormId = FindMatchedFormId(formId);
        if (!formHostRecord.Contains(matchedFormId)) {
            HILOG_WARN("form %{public}" PRId64 "not owned by this client, don't need to update flag",
                formId);
            continue;
        }

        if (isOnlyEnableUpdate) {
            // new API: this flag is used only to control enable update
            formHostRecord.SetEnableUpdate(matchedFormId, flag);
            formHostRecord.SetEnableRefresh(matchedFormId, false);
        } else {
            // old API: this flag is used to control enable update and visible update
            formHostRecord.SetEnableRefresh(matchedFormId, flag);
        }

        // set disable
        if (!flag) {
            HILOG_DEBUG("flag is disable");
            continue;
        }
        FormRecord formRecord;
        if (GetFormRecord(matchedFormId, formRecord)) {
            if (formRecord.needRefresh) {
                HILOG_DEBUG("formRecord need refresh");
                refreshForms.emplace_back(matchedFormId);
                continue;
            }
        } else {
            HILOG_WARN("not exist such form:%{public}" PRId64 "", matchedFormId);
            continue;
        }

        // if set enable flag, should check whether to refresh form
        if (!formHostRecord.IsNeedRefresh(matchedFormId)) {
            HILOG_DEBUG("host need not refresh");
            continue;
        }

        if (IsFormCached(formRecord)) {
            HILOG_DEBUG("form cached");
            formHostRecord.OnUpdate(matchedFormId, formRecord);
            formHostRecord.SetNeedRefresh(matchedFormId, false);
        } else {
            HILOG_DEBUG("form no cache");
            refreshForms.emplace_back(matchedFormId);
            continue;
        }
    }
    return ERR_OK;
}

/**
 * @brief handle update form flag.
 * @param formIDs The id of the forms.
 * @param callerToken Caller ability token.
 * @param flag form flag.
 * @param isOnlyEnableUpdate form enable update form flag.
 * @param refreshForms Refresh forms
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDataMgr::UpdateHostFormFlag(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                        bool flag, bool isOnlyEnableUpdate, std::vector<int64_t> &refreshForms)
{
    HILOG_DEBUG("start,flag:%{public}d", flag);
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        if (callerToken == itHostRecord->GetFormHostClient()) {
            HandleUpdateHostFormFlag(formIds, flag, isOnlyEnableUpdate, *itHostRecord, refreshForms);
            HILOG_DEBUG("end");
            return ERR_OK;
        }
    }
    HILOG_ERROR("can't find target client");
    return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
}
/**
 * @brief Find matched form id.
 * @param formId The form id.
 * @return Matched form id.
 */
int64_t FormDataMgr::FindMatchedFormId(const int64_t formId)
{
    uint64_t unsignedFormId = static_cast<uint64_t>(formId);
    if ((unsignedFormId & 0xffffffff00000000L) != 0) {
        return formId;
    }
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        uint64_t unsignedFormId = static_cast<uint64_t>(formId);
        uint64_t unsignedItFormRecordFirst = static_cast<uint64_t>(itFormRecord->first);
        if ((unsignedItFormRecordFirst & 0x00000000ffffffffL) == (unsignedFormId & 0x00000000ffffffffL)) {
            return itFormRecord->first;
        }
    }
    return formId;
}

/**
 * @brief Clear host data by uId.
 * @param uId The caller uId.
 */
void FormDataMgr::ClearHostDataByUId(const int uId)
{
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end();) {
        if (itHostRecord->GetCallerUid() == uId) {
            itHostRecord->CleanResource();
            itHostRecord = clientRecords_.erase(itHostRecord);
        } else {
            itHostRecord++;
        }
    }
}
/**
 * @brief Get no host temp forms.
 * @param uid The caller uid.
 * @param noHostTempFormsMap no host temp forms.
 * @param foundFormsMap Form Id list.
 */
void FormDataMgr::GetNoHostTempForms(
    const int uid, std::map<FormIdKey,
    std::set<int64_t>> &noHostTempFormsMap,
    std::map<int64_t, bool> &foundFormsMap)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (!itFormRecord->second.formTempFlag) {
            continue; // Not temp form, skip
        }

        auto itUid = std::find(itFormRecord->second.formUserUids.begin(),
            itFormRecord->second.formUserUids.end(), uid);
        if (itUid == itFormRecord->second.formUserUids.end()) {
            foundFormsMap.emplace(itFormRecord->second.formId, false);
            continue;
        }

        itFormRecord->second.formUserUids.erase(itUid);
        if (!itFormRecord->second.formUserUids.empty()) {
            continue;
        }

        FormIdKey formIdKey(itFormRecord->second.bundleName, itFormRecord->second.abilityName);
        auto itIdsSet = noHostTempFormsMap.find(formIdKey);
        if (itIdsSet == noHostTempFormsMap.end()) {
            std::set<int64_t> formIdsSet;
            formIdsSet.emplace(itFormRecord->second.formId);
            noHostTempFormsMap.emplace(formIdKey, formIdsSet);
        } else {
            itIdsSet->second.emplace(itFormRecord->second.formId);
        }
    }
}
/**
 * @brief Parse update config.
 * @param record The form record.
 * @param info The form item info.
 */
void FormDataMgr::ParseUpdateConfig(FormRecord &record, const FormItemInfo &info) const
{
    int configDuration = info.GetUpdateDuration();
    if (configDuration > 0) {
        ParseIntervalConfig(record, configDuration);
    } else {
        record.isEnableUpdate = false;
        ParseAtTimerConfig(record, info);
        ParseMultiUpdateTimeConfig(record, info);
    }
}

/**
 * @brief Parse update interval config.
 * @param record The form record.
 * @param configDuration interval duration.
 */
void FormDataMgr::ParseIntervalConfig(FormRecord &record, const int configDuration) const
{
    HILOG_INFO("configDuration:%{public}d formId: %{public}" PRId64, configDuration, record.formId);
    if (configDuration <= Constants::MIN_CONFIG_DURATION) {
        record.updateDuration = Constants::MIN_PERIOD;
    } else if (configDuration >= Constants::MAX_CONFIG_DURATION) {
        record.updateDuration = Constants::MAX_PERIOD;
    } else {
        record.updateDuration = configDuration * Constants::TIME_CONVERSION;
    }
    HILOG_INFO("end");
}

void FormDataMgr::ParseMultiUpdateTimeConfig(FormRecord &record, const FormItemInfo &info) const
{
    std::string configAtMultiTime = info.GetMultiScheduledUpdateTime();
    HILOG_INFO("ParseMultiUpdateTimeConfig updateAt:%{public}s", configAtMultiTime.c_str());
    if (configAtMultiTime.empty()) {
        return;
    }
    std::vector<std::string> timeList = FormUtil::StringSplit(configAtMultiTime, Constants::TIMES_DELIMETER);
    if (timeList.size() > Constants::UPDATE_AT_CONFIG_MAX_COUNT) {
        HILOG_ERROR("invalid config, size: %{public}zu", timeList.size());
        return;
    }
    std::vector<std::vector<int>> updateAtTimes;
    for (const auto &time : timeList) {
        std::vector<std::string> temp = FormUtil::StringSplit(time, Constants::TIME_DELIMETER);
        if (temp.size() != Constants::UPDATE_AT_CONFIG_COUNT) {
            HILOG_ERROR("invalid config");
            continue;
        }
        int hour = FormUtil::ConvertStringToInt(temp[0]);
        int min = FormUtil::ConvertStringToInt(temp[1]);
        if (hour < Constants::MIN_TIME || hour > Constants::MAX_HOUR || min < Constants::MIN_TIME || min >
            Constants::MAX_MINUTE) {
            HILOG_ERROR("invalid time, hour:%{public}d, min:%{public}d", hour, min);
            continue;
        }
        std::vector<int> newElement = {hour, min};
        updateAtTimes.push_back(newElement);
    }

    HILOG_INFO("parseAsUpdateAt updateAtTimes size:%{public}zu", updateAtTimes.size());
    if (updateAtTimes.size() > 0) {
        record.updateAtTimes = updateAtTimes;
        record.isEnableUpdate = true;
    }
}

/**
 * @brief Parse at time config.
 * @param record The form record.
 * @param info form item info.
 */
void FormDataMgr::ParseAtTimerConfig(FormRecord &record, const FormItemInfo &info) const
{
    record.updateDuration = 0;
    std::string configAtTime = info.GetScheduledUpdateTime();
    HILOG_INFO("parseAsUpdateAt updateAt:%{public}s", configAtTime.c_str());
    if (configAtTime.empty()) {
        return;
    }

    std::vector<std::string> temp = FormUtil::StringSplit(configAtTime, Constants::TIME_DELIMETER);
    if (temp.size() != Constants::UPDATE_AT_CONFIG_COUNT) {
        HILOG_ERROR("invalid config");
        return;
    }
    int hour = -1;
    int min = -1;
    hour = FormUtil::ConvertStringToInt(temp[0]);
    min = FormUtil::ConvertStringToInt(temp[1]);
    if (hour < Constants::MIN_TIME || hour > Constants::MAX_HOUR || min < Constants::MIN_TIME || min >
        Constants::MAX_MINUTE) {
        HILOG_ERROR("invalid time");
        return;
    }
    record.updateAtHour = hour;
    record.updateAtMin = min;
    record.isEnableUpdate = true;
}
/**
 * @brief check if form cached.
 * @param record The form record.
 * @return Returns ERR_OK on cached, others on not cached.
 */
bool FormDataMgr::IsFormCached(const FormRecord record)
{
    if (record.versionUpgrade) {
        return false;
    }
    return FormCacheMgr::GetInstance().NeedAcquireProviderData(record.formId);
}

/**
 * @brief Create form state host record.
 * @param provider The provider of the form state
 * @param info The form item info.
 * @param callerToken The UID of the proxy.
 * @param callingUid The UID of the proxy.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
bool FormDataMgr::CreateFormStateRecord(std::string &provider, const FormItemInfo &info,
                                        const sptr<IRemoteObject> &callerToken, int callingUid)
{
    std::lock_guard<std::mutex> lock(formStateRecordMutex_);
    auto iter = formStateRecord_.find(provider);
    if (iter != formStateRecord_.end()) {
        if (iter->second.GetFormHostClient() != callerToken) {
            iter->second.SetFormHostClient(callerToken);
        }
        return true;
    }

    FormHostRecord hostRecord;
    bool isCreated = CreateHostRecord(info, callerToken, callingUid, hostRecord);
    if (isCreated) {
        formStateRecord_.emplace(provider, hostRecord);
        return true;
    }

    return false;
}

bool FormDataMgr::CreateFormAcquireDataRecord(int64_t requestCode, const FormItemInfo &info,
                                              const sptr<IRemoteObject> &callerToken, int callingUid)
{
    std::lock_guard<std::mutex> lock(formAcquireDataRecordMutex_);
    auto iter = formAcquireDataRecord_.find(requestCode);
    if (iter != formAcquireDataRecord_.end()) {
        if (iter->second.GetFormHostClient() != callerToken) {
            iter->second.SetFormHostClient(callerToken);
        }
        return true;
    }

    FormHostRecord hostRecord;
    bool isCreated = CreateHostRecord(info, callerToken, callingUid, hostRecord);
    if (isCreated) {
        formAcquireDataRecord_.emplace(requestCode, hostRecord);
        return true;
    }

    return false;
}

ErrCode FormDataMgr::AcquireFormDataBack(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    std::lock_guard<std::mutex> lock(formAcquireDataRecordMutex_);
    auto iter = formAcquireDataRecord_.find(requestCode);
    if (iter == formAcquireDataRecord_.end()) {
        HILOG_ERROR("filed to get form state host record");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    iter->second.OnAcquireFormData(wantParams, requestCode);
    iter->second.CleanResource();
    formAcquireDataRecord_.erase(iter);
    return ERR_OK;
}

/**
 * @brief acquire form state callback.
 * @param state form state.
 * @param provider provider info.
 * @param want The want of onAcquireFormState.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
ErrCode FormDataMgr::AcquireFormStateBack(AppExecFwk::FormState state, const std::string &provider,
                                          const Want &want)
{
    std::lock_guard<std::mutex> lock(formStateRecordMutex_);
    auto iter = formStateRecord_.find(provider);
    if (iter == formStateRecord_.end()) {
        HILOG_ERROR("filed to get form state host record");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    iter->second.OnAcquireState(state, want);
    iter->second.CleanResource();
    formStateRecord_.erase(iter);
    return ERR_OK;
}

/**
 * @brief Notify the form is visible or not.
 * @param formIds Indicates the ID of the forms.
 * @param isVisible Visible or not.
 * @param callerToken Host client.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDataMgr::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                        const sptr<IRemoteObject> &callerToken)
{
    if (formIds.empty() || callerToken == nullptr) {
        HILOG_ERROR("formIds empty");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<int64_t> foundFormIds {};
    {
        HILOG_INFO("get the matched form host record by client stub");
        std::lock_guard<std::mutex> lock(formHostRecordMutex_);
        for (const FormHostRecord &record : clientRecords_) {
            if (callerToken != record.GetFormHostClient()) {
                continue;
            }
            for (const int64_t formId : formIds) {
                int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
                if (CheckInvalidForm(formId) != ERR_OK) {
                    continue;
                }
                if (!record.Contains(matchedFormId)) {
                    HILOG_ERROR("form not self-owned,form:%{public}" PRId64 ".",
                        matchedFormId);
                } else {
                    foundFormIds.push_back(matchedFormId);
                }
            }
            break;
        }
    }

    if (foundFormIds.empty()) {
        HILOG_ERROR("no valid forms found");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    for (auto matchedFormId : foundFormIds) {
        SetRecordVisible(matchedFormId, isVisible);
    }
    return ERR_OK;
}

/**
 * @brief set form record visible.
 * @param matchedFormId form id.
 * @param isVisible is visible.
 * @return Returns true if this function is successfully called; returns false otherwise.
 */
ErrCode FormDataMgr::SetRecordVisible(int64_t matchedFormId, bool isVisible)
{
    HILOG_INFO("set form record visible");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(matchedFormId);
    if (info == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    info->second.isVisible = isVisible;
    HILOG_DEBUG("set isVisible to %{public}d, formId:%{public}" PRId64 " ", isVisible, matchedFormId);
    return ERR_OK;
}

/**
 * @brief delete forms by userId.
 *
 * @param userId user ID.
 * @param removedFormIds removed userId.
 */
void FormDataMgr::DeleteFormsByUserId(const int32_t userId, std::vector<int64_t> &removedFormIds)
{
    HILOG_WARN("delete forms, userId: %{public}d", userId);
    // handle formRecords_
    std::vector<int64_t> removedTempForms;
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        auto itFormRecord = formRecords_.begin();
        while (itFormRecord != formRecords_.end()) {
            if (userId == itFormRecord->second.providerUserId) {
                if (itFormRecord->second.formTempFlag) {
                    removedTempForms.emplace_back(itFormRecord->second.formId);
                }
                removedFormIds.emplace_back(itFormRecord->second.formId);
                itFormRecord = formRecords_.erase(itFormRecord);
                FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(itFormRecord->second.formId);
            } else {
                ++itFormRecord;
            }
        }
    }

    // handle tempForms_
    if (removedTempForms.size() > 0) {
        std::lock_guard<std::mutex> lock(formTempMutex_);
        std::vector<int64_t>::iterator itTemp;
        for (itTemp = tempForms_.begin();itTemp != tempForms_.end();) {
            if (std::find(removedTempForms.begin(), removedTempForms.end(), *itTemp) != removedTempForms.end()) {
                itTemp = tempForms_.erase(itTemp);
            } else {
                itTemp++;
            }
        }
    }
}
/**
 * @brief Clear form records for st limit value test.
 */
void FormDataMgr::ClearFormRecords()
{
    {
        std::lock_guard<std::mutex> lock(formRecordMutex_);
        formRecords_.clear();
    }
    {
        std::lock_guard<std::mutex> lock(formTempMutex_);
        tempForms_.clear();
    }
}

/**
 * @brief handle get no host invalid temp forms.
 * @param userId User ID.
 * @param callingUid The UID of the proxy.
 * @param matchedFormIds The set of the valid forms.
 * @param noHostTempFormsMap The map of the no host forms.
 * @param foundFormsMap The map of the found forms.
 */
void FormDataMgr::GetNoHostInvalidTempForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                            std::map<FormIdKey, std::set<int64_t>> &noHostTempFormsMap,
                                            std::map<int64_t, bool> &foundFormsMap)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto &formRecordInfo : formRecords_) {
        int64_t formId = formRecordInfo.first;
        FormRecord &formRecord = formRecordInfo.second;

        // Checks the user id and the temp flag.
        if (!formRecord.formTempFlag || (userId != formRecord.providerUserId)) {
            continue;
        }
        // check UID
        auto iter = std::find(formRecord.formUserUids.begin(), formRecord.formUserUids.end(), callingUid);
        if (iter == formRecord.formUserUids.end()) {
            continue;
        }
        // check valid form set
        if (matchedFormIds.find(formId) != matchedFormIds.end()) {
            continue;
        }

        HILOG_DEBUG("found invalid form:%{public}" PRId64 "", formId);
        formRecord.formUserUids.erase(iter);
        if (formRecord.formUserUids.empty()) {
            FormIdKey formIdKey(formRecord.bundleName, formRecord.abilityName);
            auto itIdsSet = noHostTempFormsMap.find(formIdKey);
            if (itIdsSet == noHostTempFormsMap.end()) {
                std::set<int64_t> formIdsSet;
                formIdsSet.emplace(formId);
                noHostTempFormsMap.emplace(formIdKey, formIdsSet);
            } else {
                itIdsSet->second.emplace(formId);
            }
        } else {
            foundFormsMap.emplace(formId, false);
        }
    }
}

/**
 * @brief handle delete no host temp forms.
 * @param callingUid The UID of the proxy.
 * @param noHostTempFormsMap The map of the no host forms.
 * @param foundFormsMap The map of the found forms.
 */
void FormDataMgr::BatchDeleteNoHostTempForms(int32_t callingUid, std::map<FormIdKey,
                                             std::set<int64_t>> &noHostTempFormsMap,
                                             std::map<int64_t, bool> &foundFormsMap)
{
    std::set<FormIdKey> removableModuleSet;
    for (auto &noHostTempForm : noHostTempFormsMap) {
        FormIdKey formIdKey = noHostTempForm.first;
        std::set<int64_t> &formIdsSet = noHostTempForm.second;
        std::string bundleName = formIdKey.bundleName;
        std::string abilityName = formIdKey.abilityName;
        FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(bundleName, abilityName, formIdsSet);
        for (int64_t formId: formIdsSet) {
            foundFormsMap.emplace(formId, true);
            StopRenderingForm(formId);
            DeleteFormRecord(formId);
            DeleteTempForm(formId);
        }
    }
}

/**
 * @brief StopRenderingForm.
 * @param formId The form id.
 */
void FormDataMgr::StopRenderingForm(int32_t formId)
{
    FormRecord formrecord;
    GetFormRecord(formId, formrecord);
    FormRenderMgr::GetInstance().StopRenderingForm(formId, formrecord);
}

/**
 * @brief delete invalid temp forms.
 * @param userId User ID.
 * @param callingUid The UID of the proxy.
 * @param matchedFormIds The set of the valid forms.
 * @param removedFormsMap The map of the removed invalid forms.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormDataMgr::DeleteInvalidTempForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                            std::map<int64_t, bool> &removedFormsMap)
{
    HILOG_INFO("userId:%{public}d, callingUid:%{public}d", userId, callingUid);
    std::map<int64_t, bool> foundFormsMap {};
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap {};
    GetNoHostInvalidTempForms(userId, callingUid, matchedFormIds, noHostTempFormsMap, foundFormsMap);
    BatchDeleteNoHostTempForms(callingUid, noHostTempFormsMap, foundFormsMap);
    HILOG_DEBUG("foundFormsMap size:%{public}zu", foundFormsMap.size());
    HILOG_DEBUG("noHostTempFormsMap size:%{public}zu", noHostTempFormsMap.size());

    if (!foundFormsMap.empty()) {
        removedFormsMap.insert(foundFormsMap.begin(), foundFormsMap.end());
    }
    HILOG_INFO("done");
    return ERR_OK;
}

/**
 * @brief delete publish forms temp data
 * @param userId User ID.
 * @param bundleName BundleName.
 * @param validFormIds The set of the valid forms.
 */
void FormDataMgr::DeleteInvalidPublishForms(int32_t userId, std::string bundleName, std::set<int64_t> &validFormIds)
{
    HILOG_INFO("userId:%{public}d, bundleName:%{public}s", userId, bundleName.c_str());

    int32_t deleteNum = 0;
    std::lock_guard<std::mutex> lock(formRequestPublishFormsMutex_);
    for (auto iter = formRequestPublishForms_.begin(); iter != formRequestPublishForms_.end();) {
        int64_t formId = iter->first;
        // check valid form set
        if (validFormIds.find(formId) != validFormIds.end()) {
            ++iter;
            continue;
        }

        Want want = iter->second.first;
        if (bundleName != want.GetStringParam(Constants::PARAM_BUNDLE_NAME_KEY)) {
            ++iter;
            continue;
        }
        if (userId != want.GetIntParam(Constants::PARAM_FORM_USER_ID, -1)) {
            ++iter;
            continue;
        }
        ++deleteNum;
        iter = formRequestPublishForms_.erase(iter);
    }

    HILOG_INFO("delete num:%{public}d", deleteNum);
}

/**
 * @brief clear host data by invalid forms.
 * @param callingUid The UID of the proxy.
 * @param removedFormsMap The map of the removed invalid forms.
 * @return Returns ERR_OK on success, others on failure.
 */
int32_t FormDataMgr::ClearHostDataByInvalidForms(int32_t callingUid, std::map<int64_t, bool> &removedFormsMap)
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    std::vector<FormHostRecord>::iterator itHostRecord;
    for (itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end();) {
        if (itHostRecord->GetCallerUid() != callingUid) {
            itHostRecord++;
            continue;
        }
        for (auto &removedForm : removedFormsMap) {
            if (itHostRecord->Contains(removedForm.first)) {
                itHostRecord->DelForm(removedForm.first);
            }
        }
        if (itHostRecord->IsEmpty()) {
            itHostRecord->CleanResource();
            itHostRecord = clientRecords_.erase(itHostRecord);
        } else {
            itHostRecord++;
        }
    }
    HILOG_INFO("done");
    return ERR_OK;
}

ErrCode FormDataMgr::AddRequestPublishFormInfo(int64_t formId, const Want &want,
                                               std::unique_ptr<FormProviderData> &formProviderData)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formRequestPublishFormsMutex_);

    auto insertResult = formRequestPublishForms_.insert(
        std::make_pair(formId, std::make_pair(want, std::move(formProviderData))));
    if (!insertResult.second) {
        HILOG_ERROR("fail emplace requestPublishFormInfo");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormDataMgr::RemoveRequestPublishFormInfo(int64_t formId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formRequestPublishFormsMutex_);
    formRequestPublishForms_.erase(formId);
    return ERR_OK;
}

bool FormDataMgr::IsRequestPublishForm(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRequestPublishFormsMutex_);
    return formRequestPublishForms_.find(formId) != formRequestPublishForms_.end();
}

ErrCode FormDataMgr::GetRequestPublishFormInfo(int64_t formId, Want &want,
                                               std::unique_ptr<FormProviderData> &formProviderData)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(formRequestPublishFormsMutex_);
    auto result = formRequestPublishForms_.find(formId);
    if (result == formRequestPublishForms_.end()) {
        HILOG_INFO("invalid formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    want = result->second.first;
    formProviderData = std::move(result->second.second);
    formRequestPublishForms_.erase(result);
    return ERR_OK;
}

bool FormDataMgr::GetPackageForm(const FormRecord &record, const BundlePackInfo &bundlePackInfo,
    AbilityFormInfo &abilityFormInfo)
{
    HILOG_INFO("moduleName is %{public}s", record.moduleName.c_str());
    std::vector<PackageModule> modules = bundlePackInfo.summary.modules;
    for (const auto &cfg : modules) {
        HILOG_INFO("try module %{public}s", cfg.distro.moduleName.c_str());
        if (record.moduleName != cfg.distro.moduleName) {
            continue;
        }
        HILOG_INFO("has the same module");
        std::vector<ModuleAbilityInfo> abilities = cfg.abilities;
        std::vector<ExtensionAbilities> extensionAbilities = cfg.extensionAbilities;
        if (!abilities.empty()) {
            return GetAbilityFormInfo(record, abilities, abilityFormInfo);
        }
        if (!extensionAbilities.empty()) {
            return GetAbilityFormInfo(record, extensionAbilities, abilityFormInfo);
        }
        HILOG_WARN("no ability in module:%{public}s", record.moduleName.c_str());
        return false;
    }
    return false;
}

template<typename T>
bool FormDataMgr::GetAbilityFormInfo(const FormRecord &record, const std::vector<T> &abilities,
    AbilityFormInfo &abilityFormInfo)
{
    for (const T &abilityInfo : abilities) {
        if (abilityInfo.name != record.abilityName) {
            continue;
        }
        std::vector<AbilityFormInfo> forms = abilityInfo.forms;
        for (auto &item : forms) {
            if (IsSameForm(record, item)) {
                abilityFormInfo = item;
                HILOG_INFO("find matched abilityFormInfo");
                return true;
            }
        }
    }
    HILOG_INFO("no matched abilityFormInfo, module:%{public}s", record.moduleName.c_str());
    return false;
}

bool FormDataMgr::IsSameForm(const FormRecord &record, const AbilityFormInfo &abilityFormInfo)
{
    auto dimensionIter = Constants::DIMENSION_MAP.find(static_cast<Constants::Dimension>(record.specification));
    if (dimensionIter == Constants::DIMENSION_MAP.end()) {
        HILOG_ERROR("valid specification:%{public}d", record.specification);
        return false;
    }
    auto dimension = dimensionIter->second;
    auto supportDimensions = abilityFormInfo.supportDimensions;
    if (record.formName == abilityFormInfo.name &&
        std::find(supportDimensions.begin(), supportDimensions.end(), dimension) != supportDimensions.end()) {
        return true;
    }

    HILOG_INFO("no same form, record:%{public}s, dimension:%{public}s, abilityFormInfo:%{public}s",
        record.formName.c_str(), dimension.c_str(), abilityFormInfo.name.c_str());

    return false;
}

bool FormDataMgr::SetRecordNeedFreeInstall(int64_t formId, bool isNeedFreeInstall)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto item = formRecords_.find(formId);
    if (item == formRecords_.end()) {
        HILOG_ERROR("invalid formRecord");
        return false;
    }
    item->second.needFreeInstall = isNeedFreeInstall;
    HILOG_INFO("successfully");
    return true;
}

ErrCode FormDataMgr::CheckInvalidForm(const int64_t formId)
{
    // Checks if the formid is valid.
    if (formId <= 0) {
        HILOG_ERROR("Invalid form id");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // Gets the corresponding userId by formId.
    FormRecord formRecord;
    int64_t matchedFormId = FindMatchedFormId(formId);
    if (!GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("No matching formRecord was found for the form id");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    // Checks for cross-user operations.
    if (formRecord.providerUserId != FormUtil::GetCurrentAccountId()) {
        HILOG_ERROR("The form id corresponds to a card that is not for the currently active user");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    return ERR_OK;
}

void FormDataMgr::FillBasicRunningFormInfoByFormRecord(const FormRecord &formRecord,
                                                       RunningFormInfo &runningFormInfo) const
{
    runningFormInfo.formName = formRecord.formName;
    runningFormInfo.dimension = formRecord.specification;
    runningFormInfo.bundleName = formRecord.bundleName;
    runningFormInfo.moduleName = formRecord.moduleName;
    runningFormInfo.abilityName = formRecord.abilityName;
    runningFormInfo.description = formRecord.description;
    runningFormInfo.formLocation = formRecord.formLocation;
    runningFormInfo.formVisiblity = static_cast<FormVisibilityType>(formRecord.formVisibleNotifyState);
    runningFormInfo.lowMemoryRecycleStatus = formRecord.lowMemoryRecycleStatus;
    runningFormInfo.formBundleType = formRecord.formBundleType;
    runningFormInfo.userId = formRecord.userId;
}

ErrCode FormDataMgr::GetRunningFormInfosByFormId(const int64_t formId, RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");

    // Checks if the formid is valid.
    if (formId <= 0) {
        HILOG_ERROR("Invalid form id");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRecord formRecord;
    int64_t matchedFormId = FindMatchedFormId(formId);
    if (!GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("No matching formRecord was found for the form id");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (formRecord.providerUserId != FormUtil::GetCurrentAccountId()) {
        HILOG_ERROR("The form id corresponds to a card that is not for the currently active user");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    std::vector<FormHostRecord> formHostRecords;
    GetFormHostRecord(matchedFormId, formHostRecords);
    if (formHostRecords.empty()) {
        HILOG_ERROR("empty clientHost");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    runningFormInfo.hostBundleName = formHostRecords.begin()->GetHostBundleName();
    runningFormInfo.formId = matchedFormId;
    FillBasicRunningFormInfoByFormRecord(formRecord, runningFormInfo);
    runningFormInfo.formUsageState = FormUsageState::USED;

    return ERR_OK;
}

ErrCode FormDataMgr::HandleFormAddObserver(const std::string hostBundleName, const int64_t formId)
{
    HILOG_DEBUG("start");
    RunningFormInfo runningFormInfo;
    ErrCode ret = GetRunningFormInfosByFormId(formId, runningFormInfo);
    if (ret != ERR_OK) {
        return ret;
    }
    // if there is a full observer.
    FormObserverRecord::GetInstance().onFormAdd("all", runningFormInfo);
    // If there is a listener for the current host.
    FormObserverRecord::GetInstance().onFormAdd(hostBundleName, runningFormInfo);
    return ERR_OK;
}

ErrCode FormDataMgr::HandleFormRemoveObserver(const std::string hostBundleName, const RunningFormInfo runningFormInfo)
{
    HILOG_DEBUG("start");
    // if there is a full observer.
    FormObserverRecord::GetInstance().onFormRemove("all", runningFormInfo);
    // If there is a listener for the current host.
    FormObserverRecord::GetInstance().onFormRemove(hostBundleName, runningFormInfo);
    return ERR_OK;
}

int32_t FormDataMgr::GetTempFormsCount(int32_t &formCount)
{
    std::lock_guard<std::mutex> lock(formTempMutex_);
    formCount = static_cast<int32_t>(tempForms_.size());
    HILOG_DEBUG("current exist %{public}d temp forms in system", formCount);
    return ERR_OK;
}

int32_t FormDataMgr::GetCastFormsCount(int32_t &formCount)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (const auto &recordPair : formRecords_) {
        FormRecord record = recordPair.second;
        if (!record.formTempFlag) {
            formCount++;
        }
    }
    HILOG_DEBUG("current exist %{public}d cast forms in system", formCount);
    return ERR_OK;
}

int32_t FormDataMgr::GetHostFormsCount(const std::string &bundleName, int32_t &formCount)
{
    if (bundleName.empty()) {
        return ERR_OK;
    }
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto &record : clientRecords_) {
        if (record.GetHostBundleName() == bundleName) {
            formCount = record.GetFormsCount();
            break;
        }
    }
    HILOG_DEBUG("current exist %{public}d cast forms in host", formCount);
    return ERR_OK;
}

void FormDataMgr::GetUnusedFormInstancesByFilter(
    const FormInstancesFilter &formInstancesFilter, std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("call");
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    for (const auto& dbInfo : formDBInfos) {
        if (formInstancesFilter.bundleName != dbInfo.bundleName) {
            continue;
        }
        if (!formInstancesFilter.moduleName.empty() && formInstancesFilter.moduleName != dbInfo.moduleName) {
            continue;
        } else if (!formInstancesFilter.abilityName.empty() && formInstancesFilter.abilityName != dbInfo.abilityName) {
            continue;
        } else if (!formInstancesFilter.formName.empty() && formInstancesFilter.formName != dbInfo.formName) {
            continue;
        }
        auto item = std::find_if(formInstances.begin(), formInstances.end(),
            [&dbInfo](const auto &it) { return it.formId == dbInfo.formId; });
        if (item != formInstances.end()) {
            continue;
        }
        FormRecord dbRecord;
        ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(dbInfo.formId, dbRecord);
        if (getDbRet != ERR_OK) {
            continue;
        }
        FormInstance instance;
        instance.formId = dbInfo.formId;
        instance.specification = dbRecord.specification;
        instance.formVisiblity = static_cast<FormVisibilityType>(dbRecord.formVisibleNotifyState);
        instance.bundleName = dbRecord.bundleName;
        instance.moduleName = dbRecord.moduleName;
        instance.abilityName = dbRecord.abilityName;
        instance.formName = dbRecord.formName;
        instance.formUsageState = FormUsageState::UNUSED;
        instance.description = dbRecord.description;
        if (!dbRecord.formUserUids.empty()) {
            auto ret =
                FormBmsHelper::GetInstance().GetBundleNameByUid(*dbRecord.formUserUids.begin(), instance.formHostName);
            if (ret != ERR_OK) {
                HILOG_ERROR("Get bundleName by uid failed");
                continue;
            }
            formInstances.emplace_back(instance);
        }
    }
}

ErrCode FormDataMgr::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_DEBUG("get form instances by filter");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    std::map<int64_t, FormRecord>::iterator itFormRecord;
    if (formInstancesFilter.bundleName.empty()) {
        HILOG_ERROR("null formInstancesFilter.bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    for (itFormRecord = formRecords_.begin(); itFormRecord != formRecords_.end(); itFormRecord++) {
        if (formInstancesFilter.bundleName == itFormRecord->second.bundleName) {
            bool Needgetformhostrecordflag = true;
            if (!formInstancesFilter.moduleName.empty() &&
                formInstancesFilter.moduleName != itFormRecord->second.moduleName) {
                Needgetformhostrecordflag = false;
            } else if (!formInstancesFilter.abilityName.empty() &&
                formInstancesFilter.abilityName != itFormRecord->second.abilityName) {
                Needgetformhostrecordflag = false;
            } else if (!formInstancesFilter.formName.empty() &&
                formInstancesFilter.formName != itFormRecord->second.formName) {
                Needgetformhostrecordflag = false;
            }
            std::vector<FormHostRecord> formHostRecords;
            GetFormHostRecord(itFormRecord->second.formId, formHostRecords);
            if (Needgetformhostrecordflag) {
                FormInstance instance;
                for (auto formHostRecord : formHostRecords) {
                    instance.formHostName = formHostRecord.GetHostBundleName();
                    instance.formId = itFormRecord->second.formId;
                    instance.specification = itFormRecord->second.specification;
                    instance.formVisiblity =
                        static_cast<FormVisibilityType>(itFormRecord->second.formVisibleNotifyState);
                    instance.bundleName = itFormRecord->second.bundleName;
                    instance.moduleName = itFormRecord->second.moduleName;
                    instance.abilityName = itFormRecord->second.abilityName;
                    instance.formName = itFormRecord->second.formName;
                    instance.description = itFormRecord->second.description;
                    formInstances.emplace_back(instance);
                }
            }
        }
    }
    if (formInstancesFilter.isUnusedIncluded) {
        GetUnusedFormInstancesByFilter(formInstancesFilter, formInstances);
    }
    return (formInstances.size() == 0) ? ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED : ERR_OK;
}

ErrCode FormDataMgr::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("get form instance by formId");
    bool notFindFormRecord  = false;
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormRecord formRecord;
    notFindFormRecord  = GetFormRecordById(formId, formRecord);
    if (!notFindFormRecord) {
        std::vector<FormHostRecord> formHostRecords;
        GetFormHostRecord(formId, formHostRecords);
        if (formHostRecords.empty()) {
            HILOG_ERROR("empty clientHost");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        formInstance.formHostName = formHostRecords.begin()->GetHostBundleName();
        formInstance.formId = formRecord.formId;
        formInstance.specification = formRecord.specification;
        formInstance.formVisiblity = static_cast<FormVisibilityType>(formRecord.formVisibleNotifyState);
        formInstance.bundleName = formRecord.bundleName;
        formInstance.moduleName = formRecord.moduleName;
        formInstance.abilityName = formRecord.abilityName;
        formInstance.formName = formRecord.formName;
        formInstance.userId = formRecord.userId;
    } else {
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    HILOG_DEBUG("get form instance successfully");
    return ERR_OK;
}

ErrCode FormDataMgr::GetUnusedFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_DEBUG("call");
    FormRecord dbRecord;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbRecord);
    if (getDbRet != ERR_OK) {
        HILOG_ERROR("Get formRecord by formId failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    if (dbRecord.formUserUids.empty()) {
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    auto ret =
        FormBmsHelper::GetInstance().GetBundleNameByUid(*dbRecord.formUserUids.begin(), formInstance.formHostName);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get bundleName by uid failed");
        return ret;
    }
    formInstance.formId = formId;
    formInstance.specification = dbRecord.specification;
    formInstance.formVisiblity = static_cast<FormVisibilityType>(dbRecord.formVisibleNotifyState);
    formInstance.bundleName = dbRecord.bundleName;
    formInstance.moduleName = dbRecord.moduleName;
    formInstance.abilityName = dbRecord.abilityName;
    formInstance.formName = dbRecord.formName;
    formInstance.formUsageState = FormUsageState::UNUSED;
    formInstance.description = dbRecord.description;
    formInstance.userId = dbRecord.userId;
    return ERR_OK;
}

ErrCode FormDataMgr::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    HILOG_DEBUG("get form instance by formId");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormRecord formRecord;
    std::vector<FormHostRecord> formHostRecords;
    bool isFormRecordsEnd = GetFormRecordById(formId, formRecord);
    if (!isFormRecordsEnd) {
        GetFormHostRecord(formId, formHostRecords);
    }
    ErrCode ret = ERR_OK;
    if (!formHostRecords.empty()) {
        formInstance.formHostName = formHostRecords.begin()->GetHostBundleName();
        formInstance.formId = formRecord.formId;
        formInstance.specification = formRecord.specification;
        formInstance.formVisiblity = static_cast<FormVisibilityType>(formRecord.formVisibleNotifyState);
        formInstance.bundleName = formRecord.bundleName;
        formInstance.moduleName = formRecord.moduleName;
        formInstance.abilityName = formRecord.abilityName;
        formInstance.formName = formRecord.formName;
        formInstance.formUsageState = FormUsageState::USED;
        formInstance.description = formRecord.description;
        formInstance.userId = formRecord.userId;
    } else if (isUnusedIncluded) {
        ret = GetUnusedFormInstanceById(formId, formInstance);
    } else {
        ret = ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    HILOG_DEBUG("End");
    return ret;
}

void FormDataMgr::GetUnusedFormInfos(std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("call");
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    for (const auto& dbInfo : formDBInfos) {
        auto item = std::find_if(runningFormInfos.begin(), runningFormInfos.end(),
            [&dbInfo](const auto &it) { return it.formId == dbInfo.formId; });
        if (item != runningFormInfos.end()) {
            continue;
        }
        FormRecord dbRecord;
        ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(dbInfo.formId, dbRecord);
        if (getDbRet != ERR_OK) {
            continue;
        }
        RunningFormInfo info;
        info.formId = dbInfo.formId;
        FillBasicRunningFormInfoByFormRecord(dbRecord, info);
        info.formUsageState = FormUsageState::UNUSED;
        if (!dbRecord.formUserUids.empty()) {
            auto ret =
                FormBmsHelper::GetInstance().GetBundleNameByUid(*dbRecord.formUserUids.begin(), info.hostBundleName);
            if (ret != ERR_OK) {
                HILOG_ERROR("Get bundleName by uid failed");
                continue;
            }
            runningFormInfos.emplace_back(info);
        }
    }
}

ErrCode FormDataMgr::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto record : formRecords_) {
        if ((!record.second.formTempFlag) &&
            ((FormUtil::GetCurrentAccountId() == record.second.providerUserId) ||
            (record.second.providerUserId == Constants::DEFAULT_USER_ID))) {
            RunningFormInfo info;
            info.formId = record.first;
            FillBasicRunningFormInfoByFormRecord(record.second, info);
            info.formUsageState = FormUsageState::USED;
            std::vector<FormHostRecord> formHostRecords;
            GetFormHostRecord(record.first, formHostRecords);
            if (formHostRecords.empty()) {
                HILOG_ERROR("Get form host failed");
                continue;
            }
            info.hostBundleName = formHostRecords.begin()->GetHostBundleName();
            runningFormInfos.emplace_back(info);
        }
    }
    if (isUnusedIncluded) {
        GetUnusedFormInfos(runningFormInfos);
    }
    return ERR_OK;
}

void FormDataMgr::GetUnusedFormInfos(const std::string &bundleName, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("call");
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    for (const auto& dbInfo : formDBInfos) {
        auto item = std::find_if(runningFormInfos.begin(), runningFormInfos.end(),
            [&dbInfo](const auto &it) { return it.formId == dbInfo.formId; });
        if (item != runningFormInfos.end()) {
            continue;
        }
        for (auto uid : dbInfo.formUserUids) {
            std::string hostBundleName = "";
            auto ret = FormBmsHelper::GetInstance().GetBundleNameByUid(uid, hostBundleName);
            if (ret != ERR_OK) {
                HILOG_ERROR("Get bundleName by uid failed");
                continue;
            }
            if (hostBundleName != bundleName) {
                continue;
            }
            FormRecord dbRecord;
            ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(dbInfo.formId, dbRecord);
            if (getDbRet != ERR_OK) {
                continue;
            }
            RunningFormInfo info;
            info.formId = dbInfo.formId;
            info.hostBundleName = bundleName;
            FillBasicRunningFormInfoByFormRecord(dbRecord, info);
            info.formUsageState = FormUsageState::UNUSED;
            runningFormInfos.emplace_back(info);
        }
    }
}

ErrCode FormDataMgr::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("start");

    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto record : formRecords_) {
        std::vector<FormHostRecord> formHostRecords;
        GetFormHostRecord(record.first, formHostRecords);
        if (formHostRecords.empty()) {
            HILOG_WARN("Form has released in host, formId = %{public}" PRId64, record.first);
            continue;
        }
        auto hostBundleName = formHostRecords.begin()->GetHostBundleName();
        bool flag = (!record.second.formTempFlag) &&
            ((FormUtil::GetCurrentAccountId() == record.second.providerUserId) ||
            (record.second.providerUserId == Constants::DEFAULT_USER_ID));
        if (hostBundleName == bundleName && flag) {
            RunningFormInfo info;
            info.formId = record.first;
            info.hostBundleName = bundleName;
            FillBasicRunningFormInfoByFormRecord(record.second, info);
            info.formUsageState = FormUsageState::USED;
            runningFormInfos.emplace_back(info);
        }
    }
    if (isUnusedIncluded) {
        GetUnusedFormInfos(bundleName, runningFormInfos);
    }
    HILOG_DEBUG(
        "bundleName is %{public}s, runningFormInfo.size = %{public}zu", bundleName.c_str(), runningFormInfos.size());
    if (runningFormInfos.size() == 0) {
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    return ERR_OK;
}

void FormDataMgr::UpdateFormCloudUpdateDuration(const std::string &bundleName, int duration)
{
    HILOG_INFO("bundleName:%{public}s, duration:%{public}d", bundleName.c_str(), duration);
    std::lock_guard<std::mutex> lock(formCloudUpdateDurationMapMutex_);
    auto iter = formCloudUpdateDurationMap_.find(bundleName);
    if (iter != formCloudUpdateDurationMap_.end()) {
        iter->second = duration;
        return;
    }
    formCloudUpdateDurationMap_.emplace(bundleName, duration);
}

void FormDataMgr::RemoveFormCloudUpdateDuration(const std::string &bundleName)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formCloudUpdateDurationMapMutex_);
    auto iter = formCloudUpdateDurationMap_.find(bundleName);
    if (iter != formCloudUpdateDurationMap_.end()) {
        HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
        formCloudUpdateDurationMap_.erase(bundleName);
    }
}

int FormDataMgr::GetFormCloudUpdateDuration(const std::string &bundleName) const
{
    HILOG_DEBUG("call");
    int duration = 0;
    std::lock_guard<std::mutex> lock(formCloudUpdateDurationMapMutex_);
    auto iter = formCloudUpdateDurationMap_.find(bundleName);
    if (iter != formCloudUpdateDurationMap_.end()) {
        duration = iter->second;
        HILOG_INFO("%{public}s has form cloud update duration:%{public}d", bundleName.c_str(), duration);
    }
    return duration;
}

bool FormDataMgr::HasFormCloudUpdateDuration(const std::string &bundleName) const
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formCloudUpdateDurationMapMutex_);
    auto iter = formCloudUpdateDurationMap_.find(bundleName);
    if (iter != formCloudUpdateDurationMap_.end()) {
        HILOG_INFO("Has cloud update duration, bundleName:%{public}s", bundleName.c_str());
        return true;
    }
    HILOG_INFO("Not has cloud update duration, bundleName:%{public}s", bundleName.c_str());
    return false;
}

ErrCode FormDataMgr::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info == formRecords_.end()) {
        HILOG_INFO("form info not find, formId:%{public}" PRId64 " formLocation:%{public}d",
            formId, formLocation);
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    info->second.formLocation = (Constants::FormLocation)formLocation;
    HILOG_INFO("success, formId:%{public}" PRId64 " formLocation:%{public}d",
        formId, formLocation);
    return ERR_OK;
}

ErrCode FormDataMgr::GetRecordsByFormType(const int32_t formRefreshType,
    std::vector<FormRecord> &visibleFormRecords, std::vector<FormRecord> &invisibleFormRecords)
{
    HILOG_INFO("formRefreshType:%{public}d", formRefreshType);
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto formRecord : formRecords_) {
        if (!FormTrustMgr::GetInstance().IsTrust(formRecord.second.bundleName)) {
            HILOG_ERROR("ignore,%{public}s is unTrust.", formRecord.second.bundleName.c_str());
            continue;
        }
        if (FormBundleForbidMgr::GetInstance().IsBundleForbidden(formRecord.second.bundleName)) {
            HILOG_ERROR("ignore,%{public}s is forbidden.", formRecord.second.bundleName.c_str());
            continue;
        }
        if (formRefreshType == Constants::REFRESH_APP_FORM) {
            if (formRecord.second.formBundleType != BundleType::APP) {
                continue;
            }
        } else if (formRefreshType == Constants::REFRESH_ATOMIC_FORM) {
            if (formRecord.second.formBundleType != BundleType::ATOMIC_SERVICE) {
                continue;
            }
        } else if (formRefreshType == Constants::REFRESH_SYSTEMAPP_FORM) {
            if (!formRecord.second.isSystemApp) {
                continue;
            }
        }
        if (formRecord.second.formVisibleNotifyState == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
            visibleFormRecords.emplace_back(formRecord.second);
            continue;
        }
        invisibleFormRecords.emplace_back(formRecord.second);
    }
    return ERR_OK;
}

ErrCode FormDataMgr::SetFormLock(const int64_t formId, const bool lock)
{
    std::lock_guard<std::mutex> lockMutex(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.lockForm = lock;
    HILOG_INFO("formId:%{public}" PRId64 " lock:%{public}d", formId, lock);
    return ERR_OK;
}

ErrCode FormDataMgr::GetFormLock(const int64_t formId, bool &lock)
{
    std::lock_guard<std::mutex> lockMutex(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    lock = itFormRecord->second.lockForm;
    HILOG_INFO("formId:%{public}" PRId64 " lock:%{public}d", formId, lock);
    return ERR_OK;
}

ErrCode FormDataMgr::SetFormProtect(const int64_t formId, const bool protect)
{
    std::lock_guard<std::mutex> lockMutex(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.protectForm = protect;
    HILOG_INFO("formId:%{public}" PRId64 " protect:%{public}d", formId, protect);
    return ERR_OK;
}

ErrCode FormDataMgr::GetFormProtect(const int64_t formId, bool &protect)
{
    std::lock_guard<std::mutex> lockMutex(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    protect = itFormRecord->second.protectForm;
    HILOG_INFO("formId:%{public}" PRId64 " protect:%{public}d", formId, protect);
    return ERR_OK;
}

ErrCode FormDataMgr::SetFormEnable(const int64_t formId, const bool enable)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.enableForm = enable;
    HILOG_INFO("formId:%{public}" PRId64 " enable:%{public}d", formId, enable);
    return ERR_OK;
}

ErrCode FormDataMgr::SetRefreshDuringDisableForm(const int64_t formId, const bool enable)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.isRefreshDuringDisableForm = enable;
    HILOG_INFO("formId:%{public}" PRId64 " enable:%{public}d",
        formId, enable);
    return ERR_OK;
}

ErrCode FormDataMgr::SetUpdateDuringDisableForm(const int64_t formId, const bool enable)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.isUpdateDuringDisableForm = enable;
    HILOG_INFO("formId:%{public}" PRId64 " enable:%{public}d",
        formId, enable);
    return ERR_OK;
}

void FormDataMgr::LockForms(const std::vector<FormRecord> &&formRecords, const bool lock)
{
    HILOG_INFO("LockForms start");
    std::lock_guard<std::mutex> lockMutex(formHostRecordMutex_);
    for (auto itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        std::vector<int64_t> matchedFormIds;
        for (auto formRecord : formRecords) {
            if (itHostRecord->Contains(formRecord.formId)) {
                matchedFormIds.emplace_back(formRecord.formId);
            }
        }
        if (!matchedFormIds.empty()) {
            itHostRecord->OnLockForms(matchedFormIds, lock);
        }
    }
}

void FormDataMgr::EnableForms(const std::vector<FormRecord> &&formRecords, const bool enable)
{
    HILOG_INFO("start");
    std::lock_guard<std::mutex> lock(formHostRecordMutex_);
    for (auto itHostRecord = clientRecords_.begin(); itHostRecord != clientRecords_.end(); itHostRecord++) {
        std::vector<int64_t> matchedFormIds;
        for (auto formRecord : formRecords) {
            if (itHostRecord->Contains(formRecord.formId)) {
                matchedFormIds.emplace_back(formRecord.formId);
            }
        }
        if (!matchedFormIds.empty()) {
            itHostRecord->OnEnableForms(matchedFormIds, enable);
        }
    }
}

void FormDataMgr::GetFormIdsByUserId(int32_t userId, std::vector<int64_t> &formIds)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto formRecord : formRecords_) {
        if (formRecord.second.userId == userId) {
            formIds.emplace_back(formRecord.second.formId);
        }
    }
    HILOG_INFO("userId:%{public}d, size:%{public}zu", userId, formIds.size());
}

void FormDataMgr::SetFormVisible(int64_t formId, bool isVisible)
{
    std::lock_guard<std::shared_mutex> lock(formVisibleMapMutex_);
    auto search = formVisibleMap_.find(formId);
    if (search == formVisibleMap_.end()) {
        formVisibleMap_.emplace(formId, isVisible);
    } else {
        search->second = isVisible;
    }

    HILOG_INFO("set isVisible to %{public}d, formId:%{public}" PRId64 " ", isVisible, formId);
}

void FormDataMgr::DeleteFormVisible(int64_t formId)
{
    std::lock_guard<std::shared_mutex> lock(formVisibleMapMutex_);
    auto search = formVisibleMap_.find(formId);
    if (search != formVisibleMap_.end()) {
        formVisibleMap_.erase(formId);
    }
}

bool FormDataMgr::GetFormCanUpdate(int64_t formId)
{
    std::lock_guard<std::shared_mutex> lock(formVisibleMapMutex_);
    auto search = formVisibleMap_.find(formId);
    if (search == formVisibleMap_.end()) {
        HILOG_ERROR("form Id not find");
        formVisibleMap_.emplace(formId, true);
        return true;
    }
    return search->second;
}

void FormDataMgr::MergeFormWant(const Want &newWant, Want &oldWant)
{
    std::map<std::string, sptr<IInterface>> newWantMap;
    WantParams newWantParams = newWant.GetParams();
    WantParams oldWantParams = oldWant.GetParams();
    newWantMap = newWantParams.GetParams();
    for (auto it = newWantMap.begin(); it != newWantMap.end(); it++) {
        oldWantParams.SetParam(it->first, it->second);
    }
    oldWant.SetParams(oldWantParams);
}

void FormDataMgr::UpdateFormWant(const int64_t formId, const Want &want, FormRecord &record)
{
    if (record.wantCacheMap.size() != 0) {
        MergeFormWant(want, record.wantCacheMap[formId]);
        return;
    }
    record.wantCacheMap[formId] = want;
}

void FormDataMgr::GetFormRecordsByUserId(const int32_t userId, std::vector<FormRecord> &formRecords)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto formRecord : formRecords_) {
        if (formRecord.second.userId == userId) {
            formRecords.emplace_back(formRecord.second);
        }
    }
    HILOG_INFO("userId:%{public}d, size:%{public}zu", userId, formRecords.size());
}

/**
 * @brief get temp forms count.
 * @return Return the temp forms number.
 */
int32_t FormDataMgr::GetTempFormCount() const
{
    std::lock_guard<std::mutex> lock(formTempMutex_);
    return static_cast<int32_t>(tempForms_.size());
}

/**
 * @brief get formRecord by formId
 * @param formId form id.
 * @param formRecord form record.
 * @return Returns true on success, false on failure.
 */
bool FormDataMgr::GetFormRecordById(const int64_t formId, FormRecord &formRecord)
{
    bool notFindFormRecord  = false;
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    notFindFormRecord  = info == formRecords_.end();
    if (!notFindFormRecord) {
        formRecord = info->second;
    }
    return notFindFormRecord ;
}

void FormDataMgr::PostDelayRecheckWhetherNeedCleanFormHostTask(
    const int callerUid, const sptr<IRemoteObject> &remoteObjectOfHost)
{
    HILOG_DEBUG("start");

    auto recheckWhetherNeedCleanFormHost = [remoteObjectOfHost]() {
        FormDataMgr::GetInstance().RecheckWhetherNeedCleanFormHost(remoteObjectOfHost);
    };
    FormMgrQueue::GetInstance().ScheduleDelayTask(
        std::make_pair((int64_t)TaskType::DELETE_FORM_HOST_RECORD, static_cast<int64_t>(callerUid)),
        CLEAN_FORM_HOST_TASK_DELAY_TIME,
        recheckWhetherNeedCleanFormHost);
    HILOG_DEBUG("end");
}

FormRecord FormDataMgr::GetFormAbilityInfo(const FormRecord &record) const
{
    FormRecord newRecord;
    newRecord.bundleName = record.bundleName;
    newRecord.moduleName = record.moduleName;
    newRecord.abilityName = record.abilityName;
    newRecord.isInited = record.isInited;
    newRecord.versionUpgrade = record.versionUpgrade;
    newRecord.needFreeInstall = record.needFreeInstall;
    newRecord.providerUserId = record.providerUserId;
    return newRecord;
}

bool FormDataMgr::UpdateFormRecordSetIsExistRecycleTask(const int64_t formId, bool isExistRecycleTask)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info == formRecords_.end()) {
        HILOG_WARN("form %{public}" PRId64 " not exist", formId);
        return false;
    }
    info->second.isExistRecycleTask = isExistRecycleTask;
    HILOG_DEBUG("update form %{public}" PRId64 " isExistRecycleTask:%{public}d", formId, isExistRecycleTask);
    return true;
}

void FormDataMgr::InitLowMemoryStatus()
{
    std::string param = OHOS::system::GetParameter(MEMMORY_WATERMARK, "unknown");
    isLowMemory_.store(param == "true");
    WatchParameter(MEMMORY_WATERMARK, OnMemoryWatermarkChange, nullptr);
}

void FormDataMgr::SetIsLowMemory(bool isLowMemory)
{
    isLowMemory_.store(isLowMemory);
}

bool FormDataMgr::IsLowMemory() const
{
    return isLowMemory_.load();
}

ErrCode FormDataMgr::SetSpecification(const int64_t formId, const int32_t specification)
{
    if (specification < static_cast<int32_t>(Constants::Dimension::DIMENSION_MIN) ||
        specification > static_cast<int32_t>(Constants::Dimension::DIMENSION_MAX)) {
        HILOG_ERROR("Invalid specification");
        return ERR_APPEXECFWK_FORM_DIMENSION_ERROR;
    }
    std::lock_guard<std::mutex> lockMutex(formRecordMutex_);
    auto itFormRecord = formRecords_.find(formId);
    if (itFormRecord == formRecords_.end()) {
        HILOG_ERROR("form info not find");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    itFormRecord->second.specification = specification;
    HILOG_INFO("formId:%{public}" PRId64 " specification:%{public}d", formId, specification);
    return ERR_OK;
}

bool FormDataMgr::GetFormVisible(int64_t formId)
{
    std::lock_guard<std::shared_mutex> lock(formVisibleMapMutex_);
    auto search = formVisibleMap_.find(formId);
    if (search != formVisibleMap_.end()) {
        return search->second;
    }
    // When visibility is not set, it is visible by default
    return true;
}

void FormDataMgr::SetExpectRecycledStatus(const std::vector<int64_t> &formIds, bool isExpectRecycled)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    for (auto formId : formIds) {
        auto info = formRecords_.find(formId);
        if (info == formRecords_.end()) {
            continue;
        }
        info->second.expectRecycled = isExpectRecycled;
    }
}

bool FormDataMgr::IsExpectRecycled(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formRecordMutex_);
    auto info = formRecords_.find(formId);
    if (info == formRecords_.end()) {
        return false;
    }
    return info->second.expectRecycled;
}
}  // namespace AppExecFwk
}  // namespace OHOS
