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

#include "form_mgr_adapter.h"

#include <algorithm>
#include <cinttypes>
#include <regex>
#include <unordered_map>
#include <unordered_set>

#include "ability_manager_errors.h"
#include "form_record.h"
#include "form_info_filter.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
#include "bundle_active_client.h"
#endif
#include "fms_log_wrapper.h"
#include "form_acquire_connection.h"
#include "form_acquire_data_connection.h"
#include "form_acquire_state_connection.h"
#include "form_ams_helper.h"
#include "form_background_connection.h"
#include "form_bms_helper.h"
#include "form_bundle_forbid_mgr.h"
#include "form_cache_mgr.h"
#include "form_cast_temp_connection.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_data_proxy_mgr.h"
#include "form_db_cache.h"
#include "form_db_info.h"
#include "form_dump_mgr.h"
#include "form_ecological_rule_param.h"
#include "form_ecological_rule_service.h"
#include "form_event_notify_connection.h"
#include "form_info_mgr.h"
#include "form_mgr_errors.h"
#include "form_publish_interceptor_interface.h"
#include "form_observer_record.h"
#include "form_provider_info.h"
#include "form_provider_interface.h"
#include "form_provider_mgr.h"
#include "form_router_proxy_mgr.h"
#include "form_render_connection.h"
#include "form_render_mgr.h"
#include "form_share_mgr.h"
#include "form_supply_callback.h"
#include "form_timer_mgr.h"
#include "form_trust_mgr.h"
#include "form_util.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "js_form_state_observer_interface.h"
#include "nlohmann/json.hpp"
#include "os_account_manager.h"
#include "parameters.h"
#include "system_ability_definition.h"
#include "form_task_mgr.h"
#include "form_event_report.h"
#include "form_report.h"
#include "form_record_report.h"
#include "form_ability_connection_reporter.h"

static const int64_t MAX_NUMBER_OF_JS = 0x20000000000000;
namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t SYSTEM_UID = 1000;
constexpr int32_t API_11 = 11;
constexpr int32_t DEFAULT_USER_ID = 100;
constexpr int32_t BUNDLE_NAME_INDEX = 0;
constexpr int32_t USER_ID_INDEX = 1;
constexpr int32_t INSTANCE_SEQ_INDEX = 2;
const std::string BUNDLE_INFO_SEPARATOR = "_";
const std::string POINT_ETS = ".ets";
constexpr int DATA_FIELD = 1;
constexpr int FORM_UPDATE_LEVEL_VALUE_MAX_LENGTH = 3; // update level is 1~336, so max length is 3.
const std::string EMPTY_BUNDLE = "";
const std::string FORM_CLICK_ROUTER = "router";
const std::string FORM_CLICK_MESSAGE = "message";
const std::string FORM_CLICK_CALL = "call";
const std::string FORM_SUPPORT_ECOLOGICAL_RULEMGRSERVICE = "persist.sys.fms.support.ecologicalrulemgrservice";
constexpr int ADD_FORM_REQUEST_TIMTOUT_PERIOD = 3000;
const std::string FORM_ADD_FORM_TIMER_TASK_QUEUE = "FormMgrTimerTaskQueue";
enum class AddFormTaskType : int64_t {
    ADD_FORM_TIMER,
};
} // namespace

FormMgrAdapter::FormMgrAdapter()
{
    HILOG_DEBUG("call");
}
FormMgrAdapter::~FormMgrAdapter()
{
    HILOG_DEBUG("call");
}

void FormMgrAdapter::Init()
{
    FormDataMgr::GetInstance().GetConfigParamFormMap(Constants::VISIBLE_NOTIFY_DELAY, visibleNotifyDelay_);
    HILOG_INFO("load visibleNotifyDelayTime:%{public}d", visibleNotifyDelay_);
    serialQueue_ = std::make_shared<FormSerialQueue>(FORM_ADD_FORM_TIMER_TASK_QUEUE.c_str());
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("FormMgrAdapter Init fail, due to create serialQueue_ error");
    }
}

int FormMgrAdapter::AddForm(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    if (formId < 0 || callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    AddFormResultErrorCode states = AddFormResultErrorCode::SUCCESS;
    ErrCode ret = CheckAddFormTaskTimeoutOrFailed(formId, states);
    if (ret != ERR_OK) {
        HILOG_ERROR("AddForm Task Timeout or Failed");
        return ret;
    }
    ret = CheckFormCountLimit(formId, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("CheckFormCountLimit failed");
        return ret;
    }
    if (formId > 0) {
        FormReport::GetInstance().InsertFormId(formId);
        HILOG_DEBUG("HiSysevent Insert Formid");
    }

    // get from config info
    FormItemInfo formItemInfo;
    int32_t errCode = GetFormConfigInfo(want, formItemInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get form config info failed");
        return errCode;
    }
    // Check trust list
    formItemInfo.SetFormId(formId);
    if (!FormTrustMgr::GetInstance().IsTrust(formItemInfo.GetProviderBundleName())) {
        HILOG_ERROR("AddForm fail,%{public}s is unTrust", formItemInfo.GetProviderBundleName().c_str());
        return ERR_APPEXECFWK_FORM_NOT_TRUST;
    }
    // publish form
    if (formId > 0 && FormDataMgr::GetInstance().IsRequestPublishForm(formId)) {
        ret = AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo);
        if (ret != ERR_OK) {
            HILOG_ERROR("add request publish form failed");
            return ret;
        }
        bool tempFormFlag = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
        if (!tempFormFlag && (ret == ERR_OK)) {
            HILOG_DEBUG("Checks if there is a listener listening for adding form");
            HandleFormAddObserver(formJsInfo.formId);
        }
    }
    if (states == AddFormResultErrorCode::UNKNOWN) {
        CancelAddFormRequestTimeOutTask(formId, ret);
    }
    ret = AllotForm(formId, want, callerToken, formJsInfo, formItemInfo);
    RemoveFormIdMapElement(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("allot form failed");
    }
    return ret;
}

int FormMgrAdapter::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("call");

    bool isThemeForm = want.GetBoolParam(AppExecFwk::Constants::PARAM_THEME_KEY, false);
    if (isThemeForm) {
        HILOG_INFO("isThemeForm");
#ifdef THEME_MGR_ENABLE
        int ret = CheckFormCountLimit(0, want);
        if (ret != ERR_OK) {
            HILOG_ERROR("CheckFormCountLimit failed");
            return ret;
        }

        // generate formId
        int64_t formId = FormDataMgr::GetInstance().GenerateFormId();
        HILOG_INFO("generate formId:%{public}" PRId64, formId);
        if (formId < 0) {
            HILOG_ERROR("generate invalid formId");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        // call theme manager service to add
        ThemeManager::ThemeFormInfo themeFormInfo;
        FillThemeFormInfo(want, themeFormInfo, formId);
        ret = ThemeManager::ThemeManagerClient::GetInstance().AddForm(themeFormInfo);
        if (ret != ERR_OK) {
            HILOG_ERROR("ThemeManager AddForm failed");
            return ret;
        }

        // add record
        ret = AddThemeDBRecord(want, formId);
        if (ret != ERR_OK) {
            HILOG_ERROR("AddThemeDBRecord failed");
        }

        runningFormInfo.formId = formId;
        return ret;
#else
        HILOG_INFO("THEME_MGR_ENABLE undefined");
        return ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED;
#endif
    } else {
        HILOG_INFO("Invalid to add commom form");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
}

#ifdef THEME_MGR_ENABLE
int FormMgrAdapter::AddThemeDBRecord(const Want &want, int64_t formId)
{
    HILOG_DEBUG("call");
    FormRecord formRecord = AllotThemeRecord(want, formId);
    int ret = FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateDBRecord failed");
    }
    return ret;
}

void FormMgrAdapter::FillThemeFormInfo(const Want &want, ThemeManager::ThemeFormInfo &themeFormInfo, int64_t formId)
{
    themeFormInfo.formId = formId;
    themeFormInfo.themeFormDimension =
        static_cast<ThemeManager::ThemeFormDimension>(want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0));
    themeFormInfo.themeFormLocation =
        static_cast<ThemeManager::ThemeFormLocation>(want.GetIntParam(Constants::FORM_LOCATION_KEY, 0));
    themeFormInfo.themeFormId = want.GetStringParam(Constants::PARAM_THEME_THEME_FORM_ID);
    themeFormInfo.themeId = want.GetStringParam(Constants::PARAM_THEME_THEME_ID);
    HILOG_INFO("get theme form info, themeFormId:%{public}s, themeId:%{public}s",
        themeFormInfo.themeFormId.c_str(), themeFormInfo.themeId.c_str());
}

FormRecord FormMgrAdapter::AllotThemeRecord(const Want &want, int64_t formId)
{
    HILOG_DEBUG("call");
    FormItemInfo formInfo;
    formInfo.SetFormId(formId);
    formInfo.SetProviderBundleName(want.GetStringParam(Constants::PARAM_BUNDLE_NAME_KEY));
    formInfo.SetModuleName(want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY));
    formInfo.SetAbilityName(want.GetStringParam(Constants::PARAM_ABILITY_NAME_KEY));
    formInfo.SetSpecificationId(want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0));
    formInfo.SetFormName(want.GetStringParam(Constants::PARAM_FORM_NAME_KEY));
    formInfo.SetIsThemeForm(true);

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t currentUserId = GetCurrentUserId(callingUid);
    return FormDataMgr::GetInstance().AllotFormRecord(formInfo, callingUid, currentUserId);
}
#endif

ErrCode FormMgrAdapter::CheckFormCountLimit(const int64_t formId, const Want &want)
{
    bool tempFormFlag = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    int callingUid = IPCSkeleton::GetCallingUid();
    ErrCode checkCode = 0;
    if (tempFormFlag && ((formId == 0) || !FormRenderMgr::GetInstance().IsRerenderForRenderServiceDied(formId))) {
        if (formId > 0) {
            HILOG_ERROR("invalid tempFormId, formId:%{public}" PRId64 "", formId);
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        checkCode = FormDataMgr::GetInstance().CheckTempEnoughForm();
    } else {
        if (formId == 0) {
            // get current userId
            int32_t currentUserId = GetCurrentUserId(callingUid);
            checkCode = FormDataMgr::GetInstance().CheckEnoughForm(callingUid, currentUserId);
        }
    }
    if (checkCode != 0) {
        HILOG_ERROR("too much forms in system");
    }
    return checkCode;
}

ErrCode FormMgrAdapter::AllotForm(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo, const FormItemInfo &formItemInfo)
{
    Want newWant(want);
    bool directCallInApp = newWant.GetBoolParam(Constants::KEY_DIRECT_CALL_INAPP, false);
    // in application form
    if (formItemInfo.GetProviderBundleName() == formItemInfo.GetHostBundleName() && directCallInApp) {
        HILOG_DEBUG("form in application");
        newWant.SetParam(Constants::PARAM_FORM_HOST_TOKEN, callerToken);
    }

    WantParams wantParams = newWant.GetParams();
    // share form
    if (formId == 0 && DelayedSingleton<FormShareMgr>::GetInstance()->IsShareForm(newWant)) {
        DelayedSingleton<FormShareMgr>::GetInstance()->AddProviderData(newWant, wantParams);
    }
    //Specify the form Id
    bool specificFormFlag = false;
    if (want.HasParameter(Constants::PARAM_FORM_MIGRATE_FORM_KEY)) {
        specificFormFlag = want.GetBoolParam(Constants::PARAM_FORM_MIGRATE_FORM_KEY, false);
        HILOG_INFO("migrate_form is %{public}d", specificFormFlag);
        wantParams.Remove(Constants::PARAM_FORM_MIGRATE_FORM_KEY);
    }

    if (!formItemInfo.IsTransparencyEnabled()) {
        wantParams.Remove(Constants::PARAM_FORM_TRANSPARENCY_KEY);
    }

    ErrCode ret = 0;
    if (formId > 0) {
        if (specificFormFlag) {
            ret = AllotFormBySpecificId(formItemInfo, callerToken, wantParams, formJsInfo);
        } else {
            ret = AllotFormById(formItemInfo, callerToken, wantParams, formJsInfo);
        }
    } else {
        ret = AllotFormByInfo(formItemInfo, callerToken, wantParams, formJsInfo);
        bool tempFormFlag = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
        if (!tempFormFlag && (ret == ERR_OK)) {
            HILOG_DEBUG("Checks if there is a listener listening for adding form");
            HandleFormAddObserver(formJsInfo.formId);
        }
    }
    return ret;
}

void FormMgrAdapter::IncreaseAddFormRequestTimeOutTask(const int64_t formId)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
    auto timerTask = [this, formId]() {
        std::lock_guard<std::mutex> lock(formResultMutex_);
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            iter->second = AddFormResultErrorCode::TIMEOUT;
            condition_.notify_all();
        }
    };
    serialQueue_->ScheduleDelayTask(std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId),
        ADD_FORM_REQUEST_TIMTOUT_PERIOD, timerTask);
}

void FormMgrAdapter::CancelAddFormRequestTimeOutTask(const int64_t formId, const int result)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }
    serialQueue_->CancelDelayTask(std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId));
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto iter = formIdMap_.find(formId);
    if (iter != formIdMap_.end()) {
        if (result != ERR_OK) {
            iter->second = AddFormResultErrorCode::FAILED;
        } else {
            iter->second = AddFormResultErrorCode::SUCCESS;
        }
        condition_.notify_all();
    }
}

ErrCode FormMgrAdapter::CheckAddFormTaskTimeoutOrFailed(const int64_t formId, AddFormResultErrorCode &formStates)
{
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto result = std::find_if(formIdMap_.begin(), formIdMap_.end(), [this, formId, &formStates] (const auto elem) {
        if (elem.first == formId) {
            if (elem.second == AddFormResultErrorCode::FAILED) {
                formIdMap_.erase(formId);
                return true;
            } else if (elem.second == AddFormResultErrorCode::TIMEOUT) {
                formIdMap_.erase(formId);
                return true;
            } else if (elem.second == AddFormResultErrorCode::SUCCESS) {
                formStates = AddFormResultErrorCode::SUCCESS;
                return false;
            } else {
                formStates = AddFormResultErrorCode::UNKNOWN;
                return false;
            }
        }
        return false;
    });
    if (result != formIdMap_.end()) {
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

void FormMgrAdapter::RemoveFormIdMapElement(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(formResultMutex_);
    if (formIdMap_.find(formId) != formIdMap_.end()) {
        formIdMap_.erase(formId);
    }
}

void FormMgrAdapter::UpdateReUpdateFormMap(const int64_t formId)
{
    const int32_t jurgeMs = 100;
    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    std::lock_guard<std::mutex> lock(reUpdateFormMapMutex_);
    auto iter = reUpdateFormMap_.begin();
    while (iter != reUpdateFormMap_.end()) {
        if (currentTime - iter->second.first > jurgeMs) {
            iter = reUpdateFormMap_.erase(iter);
        } else {
            ++iter;
        }
    }
    reUpdateFormMap_[formId] = std::make_pair(currentTime, false);
}

void FormMgrAdapter::SetReUpdateFormMap(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(reUpdateFormMapMutex_);
    auto search = reUpdateFormMap_.find(formId);
    if (search != reUpdateFormMap_.end()) {
        search->second.second = true;
    }
}

ErrCode FormMgrAdapter::HandleFormAddObserver(const int64_t formId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string hostBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    // Checks if there is a observer on the current host.
    return FormDataMgr::GetInstance().HandleFormAddObserver(hostBundleName, formId);
}

ErrCode FormMgrAdapter::HandleFormRemoveObserver(const RunningFormInfo runningFormInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string hostBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    // Checks if there is a observer on the current host.
    return FormDataMgr::GetInstance().HandleFormRemoveObserver(hostBundleName, runningFormInfo);
}

int FormMgrAdapter::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("deleteForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRenderMgr::GetInstance().DeleteAcquireForbiddenTaskByFormId(formId);
#ifdef THEME_MGR_ENABLE
    FormDBInfo dbInfo;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbInfo);
    HILOG_INFO("getDbRet:%{public}d", getDbRet);
    if (getDbRet == ERR_OK && dbInfo.isThemeForm) {
        return DeleteThemeForm(formId);
    }
#endif
    return DeleteCommonForm(formId, callerToken);
}

#ifdef THEME_MGR_ENABLE
int FormMgrAdapter::DeleteThemeForm(const int64_t formId)
{
    HILOG_INFO("call");
    std::vector<int64_t> removeList;
    removeList.emplace_back(formId);
    int ret = ThemeManager::ThemeManagerClient::GetInstance().DeleteForm(removeList);
    if (ret != ERR_OK) {
        HILOG_ERROR("call ThemeManager to delete failed");
        return ret;
    }

    ret = FormDbCache::GetInstance().DeleteFormInfo(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("DeleteFormDBInfo failed");
    }
    return ret;
}
#endif

int FormMgrAdapter::DeleteCommonForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    // remove connection for in application form
    FormSupplyCallback::GetInstance()->RemoveConnection(matchedFormId, callerToken);
    FormDataProxyMgr::GetInstance().UnsubscribeFormData(matchedFormId);
    if (FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        // delete temp form if receive delete form call
        return HandleDeleteTempForm(matchedFormId, callerToken);
    }
    RunningFormInfo runningFormInfo;
    FormDataMgr::GetInstance().GetRunningFormInfosByFormId(matchedFormId, runningFormInfo);
    auto ret = HandleDeleteForm(matchedFormId, callerToken);
    if (ret != ERR_OK) {
        HILOG_ERROR("delete form failed");
        return ret;
    }
    HILOG_DEBUG("Checks if there is a listener listening for release form");
    HandleFormRemoveObserver(runningFormInfo);
    return ERR_OK;
}

int FormMgrAdapter::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("deleteForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRecord record;
    FormDataMgr::GetInstance().GetFormRecord(formId, record);
    FormRenderMgr::GetInstance().StopRenderingForm(formId, record, compId);
    return ERR_OK;
}

int FormMgrAdapter::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("releaseForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    // remove connection for in application form
    FormSupplyCallback::GetInstance()->RemoveConnection(matchedFormId, callerToken);
    if (FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        // delete temp form if receive release form call
        return HandleDeleteTempForm(matchedFormId, callerToken);
    }
    FormRecord record;
    FormDataMgr::GetInstance().GetFormRecord(formId, record);
    FormRenderMgr::GetInstance().StopRenderingForm(formId, record, "", callerToken);
    FormRecord dbRecord;
    if (FormDbCache::GetInstance().GetDBRecord(matchedFormId, dbRecord) != ERR_OK) {
        HILOG_ERROR("not exist such db form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    int callingUid = IPCSkeleton::GetCallingUid();
    bool isSelfDbFormId = (FormUtil::GetCurrentAccountId() == dbRecord.providerUserId) &&
        ((std::find(dbRecord.formUserUids.begin(), dbRecord.formUserUids.end(), callingUid)
        != dbRecord.formUserUids.end()) ? true : false);
    if (!isSelfDbFormId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    if (delCache) {
        ErrCode result = HandleReleaseForm(matchedFormId, callerToken);
        if (result != ERR_OK) {
            HILOG_ERROR("release form error");
            return result;
        }
    }

    if (!FormDataMgr::GetInstance().DeleteHostRecord(callerToken, matchedFormId)) {
        HILOG_ERROR("fail remove host record");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    if (!FormTimerMgr::GetInstance().RemoveFormTimer(matchedFormId)) {
        HILOG_ERROR("remove timer error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (!FormDataMgr::GetInstance().ExistFormRecord(formId)) {
        HILOG_ERROR("not exist such db or temp form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord hostRecord;
    bool hasRecord = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, hostRecord);
    bool isSelfId = hasRecord && hostRecord.Contains(formId);
    if (!isSelfId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    FormDataMgr::GetInstance().DeleteFormUserUid(formId, IPCSkeleton::GetCallingUid());
    if (!FormDataMgr::GetInstance().HasFormUserUids(formId)) {
        FormDataMgr::GetInstance().DeleteFormRecord(formId);
        if (!FormTimerMgr::GetInstance().RemoveFormTimer(formId)) {
            HILOG_ERROR("remove timer error");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleDeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    FormRecord dbRecord;
    if (FormDbCache::GetInstance().GetDBRecord(formId, dbRecord) != ERR_OK) {
        HILOG_ERROR("not exist such db form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    FormRecord record;
    FormDataMgr::GetInstance().GetFormRecord(formId, record);
    FormRenderMgr::GetInstance().StopRenderingForm(formId, record, "", callerToken);
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
        record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_REMOVED);
#endif
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCurrentAccountId();
    bool isSelfDbFormId = (userId == dbRecord.providerUserId) && ((std::find(dbRecord.formUserUids.begin(),
        dbRecord.formUserUids.end(), callingUid) != dbRecord.formUserUids.end()) ? true : false);
    if (!isSelfDbFormId) {
        HILOG_ERROR("not self form:%{public}" PRId64 ", callingUid:%{public}d", formId, callingUid);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    ErrCode result = HandleDeleteFormCache(dbRecord, callingUid, formId);
    if (result != ERR_OK) {
        return result;
    }

    if (!FormDataMgr::GetInstance().DeleteHostRecord(callerToken, formId)) {
        HILOG_ERROR("fail remove host record");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, userId);
#endif
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleDeleteTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int uid = IPCSkeleton::GetCallingUid();
    FormRecord record;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    bool isSelfTempFormId = false;
    if (isFormRecExist && record.formTempFlag) {
        isSelfTempFormId = (FormUtil::GetCurrentAccountId() == record.providerUserId) &&
            ((std::find(record.formUserUids.begin(), record.formUserUids.end(), uid) !=
            record.formUserUids.end()) ? true : false);
    }
    if (!isSelfTempFormId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    FormRenderMgr::GetInstance().StopRenderingForm(formId, record, "", callerToken);
    FormDataMgr::GetInstance().DeleteFormUserUid(formId, uid);
    if (!FormDataMgr::GetInstance().HasFormUserUids(formId)) {
        int result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, record);
        if (result != ERR_OK) {
            HILOG_ERROR("fail");
            FormDataMgr::GetInstance().AddFormUserUid(formId, uid);
            return result;
        }
        if (!FormDataMgr::GetInstance().DeleteTempForm(formId)) {
            HILOG_ERROR("formId not exist");
            return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        }
        FormDataMgr::GetInstance().DeleteFormRecord(formId);
        if (!FormCacheMgr::GetInstance().DeleteData(formId)) {
            HILOG_ERROR("fail remove cache data");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    if (!FormDataMgr::GetInstance().DeleteHostRecord(callerToken, formId)) {
        HILOG_ERROR("fail remove host record");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    HILOG_DEBUG("record.formUserUids size:%{public}zu", record.formUserUids.size());
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleDeleteFormCache(FormRecord &dbRecord, const int uid, const int64_t formId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    auto iter = std::find(dbRecord.formUserUids.begin(), dbRecord.formUserUids.end(), uid);
    if (iter != dbRecord.formUserUids.end()) {
        dbRecord.formUserUids.erase(iter);
    }

    ErrCode result = ERR_OK;
    int32_t deleteFormError = ERR_OK;
    if (dbRecord.formUserUids.empty()) {
        result = FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, dbRecord);
        if (result != ERR_OK) {
            HILOG_ERROR("notify providerForm delete failed");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : result;
        }
        if (!FormDataMgr::GetInstance().DeleteFormRecord(formId)) {
            HILOG_ERROR("fail remove cache data");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        }
        if (result = FormDbCache::GetInstance().DeleteFormInfo(formId); result != ERR_OK) {
            HILOG_ERROR("fail remove db data");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : result;
        }

        int32_t matchCount = FormDbCache::GetInstance().GetMatchCount(dbRecord.bundleName, dbRecord.moduleName);
        if (matchCount == 0) {
            FormBmsHelper::GetInstance().NotifyModuleRemovable(dbRecord.bundleName, dbRecord.moduleName);
        }

        if (!FormCacheMgr::GetInstance().DeleteData(formId)) {
            HILOG_ERROR("fail remove cache data");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        if (!FormTimerMgr::GetInstance().RemoveFormTimer(formId)) {
            HILOG_ERROR("remove timer error");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        return deleteFormError;
    }

    if (result = FormDbCache::GetInstance().UpdateDBRecord(formId, dbRecord); result != ERR_OK) {
        return result;
    }

    HILOG_DEBUG("dbRecord.formUserUids size:%{public}zu", dbRecord.formUserUids.size());
    FormBmsHelper::GetInstance().NotifyModuleNotRemovable(dbRecord.bundleName, dbRecord.moduleName);
    FormDataMgr::GetInstance().DeleteFormUserUid(formId, uid);
    return result;
}

int FormMgrAdapter::UpdateForm(const int64_t formId, const int32_t callingUid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("formId:%{public}" PRId64, formId);

    // check formId and bundleName
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // find matched formId
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);

    // check exist and get the formRecord
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    // Checks if the form provider is the currently active user.
    if (FormUtil::GetCurrentAccountId() != formRecord.providerUserId) {
        HILOG_ERROR("not under current user");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    // check bundleName match
    if (formRecord.uid != callingUid) {
        HILOG_ERROR("not match providerUid:%{public}d and callingUid:%{public}d", formRecord.uid, callingUid);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t ret = ERR_OK;
    if (formRecord.uiSyntax == FormType::ETS) {
        WantParams wantParams;
        ret = FormRenderMgr::GetInstance().UpdateRenderingForm(formId, formProviderData, wantParams, false);
    } else {
        // update Form
        ret = FormProviderMgr::GetInstance().UpdateForm(matchedFormId, formRecord, formProviderData);
    }

    if (!formDataProxies.empty()) {
        FormDataProxyMgr::GetInstance().UpdateSubscribeFormData(matchedFormId, formDataProxies);
    }
    return ret;
}

int FormMgrAdapter::RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("invalid formId or callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    if (!FormDataMgr::GetInstance().ExistFormRecord(matchedFormId)) {
        HILOG_ERROR("not exist such formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord formHostRecord;
    bool isHostExist = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, formHostRecord);
    if (!isHostExist) {
        HILOG_ERROR("can't find target client");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!formHostRecord.Contains(matchedFormId)) {
        HILOG_ERROR("form not self-owned");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    HILOG_INFO("find target client");
    Want reqWant(want);
    int32_t currentActiveUserId = FormUtil::GetCurrentAccountId();
    reqWant.SetParam(Constants::PARAM_FORM_USER_ID, currentActiveUserId);
    return FormProviderMgr::GetInstance().RefreshForm(matchedFormId, reqWant, true);
}

void FormMgrAdapter::SetVisibleChange(const int64_t formId, const int32_t formVisibleType)
{
    if (formId <= 0
        || (formVisibleType != Constants::FORM_VISIBLE && formVisibleType != Constants::FORM_INVISIBLE)) {
        HILOG_WARN("param is not right");
        return;
    }

    bool isVisible = (formVisibleType == Constants::FORM_VISIBLE) ? true : false;
    FormRenderMgr::GetInstance().SetVisibleChange(formId, isVisible);
}

ErrCode FormMgrAdapter::NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    int64_t matchedFormId = 0;
    int32_t userId = FormUtil::GetCurrentAccountId();
    std::map<std::string, std::vector<int64_t>> eventMaps;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::vector<int64_t> checkFormIds;

    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("formId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        FormRecord formRecord;

        if (!isFormShouldUpdateProviderInfoToHost(matchedFormId, userId, callerToken, formRecord)) {
            continue;
        }
        SetVisibleChange(matchedFormId, formVisibleType);
        PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
        checkFormIds.push_back(formId);
        // Update info to host and check if the form was created by the system application.
        if ((!UpdateProviderInfoToHost(matchedFormId, userId, callerToken, formVisibleType, formRecord)) ||
            (!formRecord.isSystemApp)) {
            continue;
        }

        // Check the value of formVisibleNotify.
        AppExecFwk::ApplicationInfo info;

        if (!IN_PROCESS_CALL(iBundleMgr->GetApplicationInfo(formRecord.bundleName,
            AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO, formRecord.providerUserId, info))) {
            HILOG_ERROR("get ApplicationInfo failed");
            return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
        }

        if (!info.formVisibleNotify) {
            HILOG_DEBUG("the value of formVisibleNotify is false");
            continue;
        }

        // Create eventMaps
        if (!CreateHandleEventMap(matchedFormId, formRecord, eventMaps)) {
            continue;
        }
    }

    FormTaskMgr::GetInstance().PostVisibleNotify(
        (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) ? checkFormIds : formIds,
        formInstanceMaps, eventMaps, formVisibleType, visibleNotifyDelay_, callerToken);
    return ERR_OK;
}

bool FormMgrAdapter::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("call");
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    int ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        HILOG_ERROR("GetHapTokenInfo error with ret:%{public}d", ret);
        return false;
    }

    std::string bundleName = hapTokenInfo.bundleName;
    int32_t userId = hapTokenInfo.userID;
    HILOG_INFO("bundleName:%{public}s, userId:%{public}d, instIndex:%{public}d", bundleName.c_str(), userId,
        hapTokenInfo.instIndex);

    if (hapTokenInfo.instIndex != 0) {
        HILOG_INFO("The app is a clone application.");
        return false;
    }

    std::vector<FormRecord> formInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formInfos)) {
        return false;
    }

    for (const auto& formRecord : formInfos) {
        HILOG_DEBUG("query record, visible:%{public}d, userId:%{public}d", formRecord.formVisibleNotifyState, userId);
        if (formRecord.formVisibleNotifyState == static_cast<int32_t>(FormVisibilityType::VISIBLE) &&
            formRecord.userId == userId) {
                return true;
        }
    }

    return false;
}

void FormMgrAdapter::PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps)
{
    std::string specialFlag = "#";
    bool isVisibility = (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE));
    FormInstance formInstance;
    // Get the updated card status
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormDataMgr::GetInstance().GetFormInstanceById(matchedFormId, false, formInstance);
    std::string formHostName = formInstance.formHostName;
    std::string formAllHostName = EMPTY_BUNDLE;
    if (formVisibleType == static_cast<int32_t>(formInstance.formVisiblity)) {
        return;
    }
    for (auto formObserver : formObservers_) {
        if (formObserver.first == formHostName + specialFlag + std::to_string(isVisibility) ||
            formObserver.first == formAllHostName + specialFlag + std::to_string(isVisibility)) {
            auto observer = formInstanceMaps.find(formObserver.first);
            if (observer == formInstanceMaps.end()) {
                std::vector<FormInstance> formInstances;
                formInstance.formVisiblity = static_cast<FormVisibilityType>(formVisibleType);
                formInstances.emplace_back(formInstance);
                formInstanceMaps.emplace(formObserver.first, formInstances);
            } else {
                observer->second.emplace_back(formInstance);
            }
        }
    }
}

void FormMgrAdapter::HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("start");
    FilterDataByVisibleType(formInstanceMaps, eventMaps, formVisibleType);
    for (auto formObserver : formObservers_) {
        NotifyWhetherFormsVisible(formObserver.first, formObserver.second, formInstanceMaps, formVisibleType);
    }
    for (auto iter = eventMaps.begin(); iter != eventMaps.end(); iter++) {
        if (HandleEventNotify(iter->first, iter->second, formVisibleType) != ERR_OK) {
            HILOG_WARN("HandleEventNotify error, key is %{public}s", iter->first.c_str());
        }
    }
    if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
        FormDataProxyMgr::GetInstance().EnableSubscribeFormData(formIds);
    } else if (formVisibleType == static_cast<int32_t>(FormVisibilityType::INVISIBLE)) {
        FormDataProxyMgr::GetInstance().DisableSubscribeFormData(formIds);
    }
    
    int32_t userId = FormUtil::GetCurrentAccountId();
    std::vector<int64_t> needConFormIds;
    if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
        FormRenderMgr::GetInstance().checkConnectionsFormIds(formIds, userId, needConFormIds);
    }

    if (!needConFormIds.empty()) {
        HILOG_ERROR("reAddConnections, size: %{public}zu", needConFormIds.size());
        FormRenderMgr::GetInstance().reAddConnections(needConFormIds, userId, callerToken);
    }
}

void FormMgrAdapter::NotifyWhetherFormsVisible(const std::string &bundleName,
    std::vector<sptr<IRemoteObject>> &remoteObjects,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps, const int32_t formVisibleType)
{
    HILOG_DEBUG("bundleName:%{public}s, remoteObjects:%{public}d", bundleName.c_str(), (int)remoteObjects.size());
    for (auto remoteObject : remoteObjects) {
        sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
            iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
        auto observer = formInstanceMaps.find(bundleName);
        if (observer != formInstanceMaps.end()) {
            if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
                remoteJsFormStateObserver->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE,
                    bundleName, observer->second);
            } else if (formVisibleType == static_cast<int32_t>(FormVisibilityType::INVISIBLE)) {
                remoteJsFormStateObserver->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE,
                    bundleName, observer->second);
            }
        }
    }
}

void FormMgrAdapter::FilterDataByVisibleType(std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> &eventMaps, const int32_t formVisibleType)
{
    HILOG_DEBUG("start");
    std::map<int64_t, FormRecord> restoreFormRecords;
    FilterFormInstanceMapsByVisibleType(formInstanceMaps, formVisibleType, restoreFormRecords);
    FilterEventMapsByVisibleType(eventMaps, formVisibleType, restoreFormRecords);

    for (auto formRecordEntry : restoreFormRecords) {
        FormRecord formRecord = formRecordEntry.second;
        formRecord.isNeedNotify = false;
        HILOG_INFO("formRecord no need notify, formId:%{public}" PRId64 ".", formRecord.formId);
        if (!FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord)) {
            HILOG_ERROR("update restoreFormRecords failed, formId:%{public}" PRId64 ".", formRecord.formId);
        }
    }
}

void FormMgrAdapter::FilterFormInstanceMapsByVisibleType(
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords)
{
    for (auto iter = formInstanceMaps.begin(); iter != formInstanceMaps.end();) {
        std::vector<FormInstance> formInstances = iter->second;
        HILOG_DEBUG("bundName:%{public}s, formInstances:%{public}d", iter->first.c_str(), (int)formInstances.size());
        auto instanceIter = formInstances.begin();
        while (instanceIter != formInstances.end()) {
            FormRecord record;
            if (!FormDataMgr::GetInstance().GetFormRecord(instanceIter->formId, record)) {
                HILOG_WARN("get formRecord failed! formId:%{public}" PRId64 ".", instanceIter->formId);
                ++instanceIter;
                continue;
            }
            if (record.formVisibleNotifyState != formVisibleType) {
                HILOG_INFO("erase formId:%{public}" PRId64 ", formVisibleNotifyState:%{public}d",
                    instanceIter->formId, record.formVisibleNotifyState);
                restoreFormRecords[record.formId] = record;
                instanceIter = formInstances.erase(instanceIter);
                continue;
            }
            if (!record.isNeedNotify) {
                HILOG_INFO("erase formId:%{public}" PRId64
                    ", isNeedNotify:%{public}d, formVisibleNotifyState:%{public}d",
                    instanceIter->formId, record.isNeedNotify, record.formVisibleNotifyState);
                instanceIter = formInstances.erase(instanceIter);
                continue;
            }
            ++instanceIter;
        }
        if (formInstances.empty()) {
            HILOG_INFO("formInstanceMaps remove bundName:%{public}s", iter->first.c_str());
            iter = formInstanceMaps.erase(iter);
            continue;
        }
        ++iter;
    }
}

void FormMgrAdapter::FilterEventMapsByVisibleType(std::map<std::string, std::vector<int64_t>> &eventMaps,
    const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords)
{
    for (auto iter = eventMaps.begin(); iter != eventMaps.end();) {
        std::vector<int64_t> formIds = iter->second;
        HILOG_DEBUG("bundName:%{public}s, eventMaps:%{public}d", iter->first.c_str(), (int)formIds.size());
        auto formItr = formIds.begin();
        while (formItr != formIds.end()) {
            FormRecord record;
            if (!FormDataMgr::GetInstance().GetFormRecord(*formItr, record)) {
                HILOG_WARN("get formRecord failed! formId:%{public}" PRId64 ".", *formItr);
                ++formItr;
                continue;
            }
            if (record.formVisibleNotifyState != formVisibleType) {
                HILOG_INFO("erase formId:%{public}" PRId64 ", formVisibleNotifyState:%{public}d",
                    *formItr, record.formVisibleNotifyState);
                restoreFormRecords[record.formId] = record;
                formItr = formIds.erase(formItr);
                continue;
            }
            if (!record.isNeedNotify) {
                HILOG_INFO("erase formId:%{public}" PRId64
                    ", isNeedNotify:%{public}d, formVisibleNotifyState %{public}d",
                    *formItr, record.isNeedNotify, record.formVisibleNotifyState);
                formItr = formIds.erase(formItr);
                continue;
            }
            ++formItr;
        }
        if (formIds.empty()) {
            HILOG_INFO("eventMaps remove bundName:%{public}s", iter->first.c_str());
            iter = eventMaps.erase(iter);
            continue;
        }
        ++iter;
    }
}

int FormMgrAdapter::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("invalid formId or callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    if (!FormDataMgr::GetInstance().ExistFormRecord(matchedFormId) ||
        !FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        HILOG_ERROR("not exist such temp form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord record;
    bool hasRecord = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, record);
    if (!hasRecord || !record.Contains(matchedFormId)) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = GetCurrentUserId(callingUid);
    int checkCode = FormDataMgr::GetInstance().CheckEnoughForm(callingUid, userId);
    if (checkCode != 0) {
        HILOG_ERROR("%{public}" PRId64 " failed,because if too mush forms", matchedFormId);
        return checkCode;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    int bindSupplierCheckCode = HandleCastTempForm(matchedFormId, formRecord);
    if (bindSupplierCheckCode != 0) {
        HILOG_ERROR("cast temp form bindSupplier failed");
        return bindSupplierCheckCode;
    }

    if (!FormDataMgr::GetInstance().DeleteTempForm(matchedFormId)) {
        HILOG_ERROR("delete temp form error, formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    if (!FormDataMgr::GetInstance().ModifyFormTempFlag(matchedFormId, false)) {
        HILOG_ERROR("modify form temp flag error, formId:%{public}" PRId64 ".",
            matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    if (!FormDataMgr::GetInstance().AddFormUserUid(matchedFormId, callingUid)) {
        HILOG_ERROR("add form user uid error, formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    ErrCode errorCode = FormDbCache::GetInstance().UpdateDBRecord(matchedFormId, formRecord);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("update db record error, formId:%{public}" PRId64 ".", matchedFormId);
        return errorCode;
    }

    // start timer
    return AddFormTimer(formRecord);
}

ErrCode FormMgrAdapter::HandleCastTempForm(const int64_t formId, const FormRecord &record)
{
    HILOG_DEBUG("cast temp form to normal form, notify supplier, package:%{public}s, class:%{public}s",
        record.bundleName.c_str(), record.abilityName.c_str());
    sptr<IAbilityConnection> castTempConnection = new FormCastTempConnection(formId,
        record.bundleName, record.abilityName);

    Want want;
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    want.SetElementName(record.bundleName, record.abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, castTempConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

int FormMgrAdapter::DumpStorageFormInfos(std::string &formInfos) const
{
    std::vector<FormDBInfo> formDBInfos;
    FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
    if (formDBInfos.empty()) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    std::sort(formDBInfos.begin(), formDBInfos.end(),
        [] (const FormDBInfo &formDBInfoA, const FormDBInfo &formDBInfoB) -> bool {
        return formDBInfoA.formId < formDBInfoB.formId;
    });
    FormDumpMgr::GetInstance().DumpStorageFormInfos(formDBInfos, formInfos);
    return ERR_OK;
}

int FormMgrAdapter::DumpTemporaryFormInfos(std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormRecord> formRecordInfos;
    if (!FormDataMgr::GetInstance().GetTempFormRecord(formRecordInfos)) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    return ERR_OK;
}

int FormMgrAdapter::DumpStaticBundleFormInfos(std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormInfo> bundleFormInfos;
    if (FormInfoMgr::GetInstance().GetAllFormsInfo(bundleFormInfos) != ERR_OK) {
        HILOG_ERROR("GetAllFormsInfo failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    return ERR_OK;
}

int FormMgrAdapter::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const
{
    HILOG_INFO("call");
    std::vector<FormRecord> formRecordInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formRecordInfos)) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    /**
     * The updateDuration stored in FormRecord is the config.json configuration.
     * The app gallery may modify the updateDuration.
     * The real updateDuration value needs to be obtained from FormTimerMgr.
     */
    for (auto &formRecord : formRecordInfos) {
        FormTimer formTimer;
        if (formRecord.isEnableUpdate && formRecord.updateDuration > 0 &&
            FormTimerMgr::GetInstance().GetIntervalTimer(formRecord.formId, formTimer)) {
            formRecord.updateDuration = formTimer.period;
        }
    }
    FormDumpMgr::GetInstance().DumpFormInfos(formRecordInfos, formInfos);
    return ERR_OK;
}

int FormMgrAdapter::DumpHasFormVisible(const std::string &bundleInfo, std::string &formInfos) const
{
    HILOG_INFO("bundleInfo:%{public}s", bundleInfo.c_str());
    std::vector<std::string> bundleInfoList = FormUtil::StringSplit(bundleInfo, BUNDLE_INFO_SEPARATOR);
    size_t size = bundleInfoList.size();
    if (size == 0) {
        HILOG_ERROR("args size is zero");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // resolve bundle info
    std::string bundleName = bundleInfoList[BUNDLE_NAME_INDEX];
    int32_t userId = DEFAULT_USER_ID;
    int32_t instIndex = 0;
    if (size > USER_ID_INDEX) {
        userId = std::stoi(bundleInfoList[USER_ID_INDEX]);
        if (size > INSTANCE_SEQ_INDEX) {
            instIndex = std::stoi(bundleInfoList[INSTANCE_SEQ_INDEX]);
        }
    }
    HILOG_INFO("resolve bundleInfo, bundleName:%{public}s, userId:%{public}d, instIndex:%{public}d",
        bundleName.c_str(), userId, instIndex);
    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, instIndex);
    FormDumpMgr::GetInstance().DumpHasFormVisible(tokenId, bundleName, userId, instIndex, formInfos);
    return ERR_OK;
}

int FormMgrAdapter::DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const
{
    HILOG_INFO("call");
    int reply = ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    FormRecord formRecord;
    if (FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        /**
         * The updateDuration stored in FormRecord is the config.json configuration.
         * The app gallery may modify the updateDuration.
         * The real updateDuration value needs to be obtained from FormTimerMgr.
         */
        FormTimer formTimer;
        if (formRecord.isEnableUpdate && formRecord.updateDuration > 0 &&
            FormTimerMgr::GetInstance().GetIntervalTimer(formRecord.formId, formTimer)) {
            formRecord.updateDuration = formTimer.period;
        }
        FormDumpMgr::GetInstance().DumpFormInfo(formRecord, formInfo);
        reply = ERR_OK;
    }

    std::vector<std::string> subscribedKeys;
    int32_t count = 0;
    if (reply == ERR_OK) {
        FormDataProxyMgr::GetInstance().GetFormSubscribeInfo(formId, subscribedKeys, count);
        FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    }

    std::vector<FormHostRecord> formHostRecords;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, formHostRecords);
    for (const auto &iter : formHostRecords) {
        FormDumpMgr::GetInstance().DumpFormHostInfo(iter, formInfo);
        reply = ERR_OK;
    }

    return reply;
}

int FormMgrAdapter::DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const
{
    HILOG_INFO("call");
    FormTimer formTimer;
    UpdateAtItem updateAtItem;
    DynamicRefreshItem dynamicItem;
    bool resultInter = FormTimerMgr::GetInstance().GetIntervalTimer(formId, formTimer);
    bool resultUpdate = FormTimerMgr::GetInstance().GetUpdateAtTimer(formId, updateAtItem);
    bool resultDynamic = FormTimerMgr::GetInstance().GetDynamicItem(formId, dynamicItem);
    HILOG_INFO("resultInter:%{public}d,resultUpdate:%{public}d,resultDynamic:%{public}d",
        resultInter, resultUpdate, resultDynamic);
    if (resultInter || resultUpdate || resultDynamic) {
        isTimingService = "true";
    } else {
        isTimingService = "false";
    }
    return ERR_OK;
}

int FormMgrAdapter::DumpFormRunningFormInfos(std::string &runningFormInfosResult) const
{
    HILOG_INFO("call");
    std::vector<RunningFormInfo> runningFormInfos;
    auto ret = FormMgrAdapter::GetInstance().GetRunningFormInfos(true, runningFormInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("GetRunningFormInfos error");
        return ret;
    }

    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, runningFormInfosResult);
    return ERR_OK;
}

ErrCode FormMgrAdapter::GetFormConfigInfo(const Want &want, FormItemInfo &formConfigInfo)
{
    HILOG_DEBUG("GetFormConfigInfo start");
    BundleInfo bundleInfo;
    std::string packageName;
    ErrCode errCode = GetBundleInfo(want, bundleInfo, packageName);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get bundle info failed");
        return errCode;
    }

    FormInfo formInfo;
    errCode = GetFormInfo(want, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get target form info failed");
        return errCode;
    }
    if (!formInfo.IsValid()) {
        HILOG_ERROR("invalid formInfo");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    errCode = GetFormItemInfo(want, bundleInfo, formInfo, formConfigInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Get form item info failed");
        return errCode;
    }
    formConfigInfo.SetPackageName(packageName);
    formConfigInfo.SetDeviceId(want.GetElement().GetDeviceID());

    if (!formConfigInfo.IsValidItem()) {
        HILOG_ERROR("invalid inputParamItemInfo");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    int formLocation = want.GetParams().GetIntParam(Constants::FORM_LOCATION_KEY,
        static_cast<int>(Constants::FormLocation::OTHER));
    if (formLocation < static_cast<int32_t>(Constants::FormLocation::OTHER) ||
            formLocation > static_cast<int32_t>(Constants::FormLocation::AI_SUGGESTION)) {
        HILOG_ERROR("formLocation not FormLocation enum,formLocation = %{public}d", formLocation);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    formConfigInfo.SetFormLocation((Constants::FormLocation)formLocation);
    
    int renderingMode = want.GetParams().GetIntParam(Constants::PARAM_FORM_RENDERINGMODE_KEY,
        static_cast<int>(Constants::RenderingMode::FULL_COLOR));
    formConfigInfo.SetRenderingMode((Constants::RenderingMode)renderingMode);

    bool isFormBundleForbidden = FormBundleForbidMgr::GetInstance().IsBundleForbidden(
        formConfigInfo.GetProviderBundleName());
    formConfigInfo.SetEnableForm(!isFormBundleForbidden);
    HILOG_DEBUG("GetFormConfigInfo end,formLocation = %{public}d,enable is %{public}d",
        formLocation, isFormBundleForbidden);

    return ERR_OK;
}

void FormMgrAdapter::CheckUpdateFormRecord(const int64_t formId, const FormItemInfo &info, FormRecord &record)
{
    bool needUpdate = false;
    if (record.recycleStatus != RecycleStatus::NON_RECYCLABLE) {
        record.recycleStatus = RecycleStatus::NON_RECYCLABLE;
        needUpdate = true;
    }
    if (record.formLocation != info.GetFormLocation()) {
        record.formLocation = info.GetFormLocation();
        needUpdate = true;
    }
    if (needUpdate) {
        FormDataMgr::GetInstance().UpdateFormRecord(formId, record);
    }
}

ErrCode FormMgrAdapter::AllotFormById(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_INFO("call");
    int64_t formId = FormDataMgr::GetInstance().PaddingUdidHash(info.GetFormId());
    FormRecord record;
    bool hasRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    record.enableForm = info.IsEnableForm();
    if (hasRecord) {
        CheckUpdateFormRecord(formId, info, record);
        if (record.formTempFlag && !FormRenderMgr::GetInstance().IsRerenderForRenderServiceDied(formId)) {
            HILOG_ERROR("addForm can't acquire tempForm when select formId");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    record.formLocation = info.GetFormLocation();

    // ark ts form can only exist with one form host
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (info.GetUiSyntax() == FormType::ETS &&
        !FormDbCache::GetInstance().IsHostOwner(formId, callingUid)) {
        HILOG_ERROR("the specified form id does not exist in caller. formId:%{public}s",
            std::to_string(formId).c_str());
        return ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID;
    }

    int32_t currentUserId = GetCurrentUserId(callingUid);
    if (hasRecord && (record.providerUserId == currentUserId)) {
        if (!info.IsMatch(record)) {
            HILOG_ERROR("formId and item info not match:%{public}" PRId64 "", formId);
            return ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID;
        }
        return AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo);
    }

    // find in db but not in cache
    FormRecord dbRecord;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbRecord);
    if (getDbRet == ERR_OK && (dbRecord.providerUserId == currentUserId)) {
        return AddNewFormRecord(info, formId, callerToken, wantParams, formInfo);
    }

    HILOG_INFO("no such formId:%{public}" PRId64, formId);

    // delete form data in provider
    FormRecord delRecord;
    delRecord.bundleName = info.GetProviderBundleName();
    delRecord.abilityName = info.GetAbilityName();
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, delRecord);

    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}

ErrCode FormMgrAdapter::AddExistFormRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const FormRecord &record, const int64_t formId, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_INFO("add exist formRecord, formId:%{public}" PRId64, formId);
    // allot form host record
    int callingUid = IPCSkeleton::GetCallingUid();
    bool isCreated = FormDataMgr::GetInstance().AllotFormHostRecord(info, callerToken, formId, callingUid);
    if (!isCreated) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    FormRecord newRecord(record);
    std::string cacheData;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool hasCacheData = FormCacheMgr::GetInstance().GetData(formId, cacheData, imageDataMap);
    if (hasCacheData) {
        newRecord.formProviderInfo.SetFormDataString(cacheData);
        newRecord.formProviderInfo.SetImageDataMap(imageDataMap);
    } else {
        SetReUpdateFormMap(formId);
    }
    FormRenderMgr::GetInstance().RenderForm(newRecord, wantParams, callerToken);
    if (newRecord.needRefresh || newRecord.needAddForm
        || FormCacheMgr::GetInstance().NeedAcquireProviderData(newRecord.formId)
        || wantParams.HasParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY)) {
        HILOG_INFO("acquire ProviderFormInfo async, formId:%{public}" PRId64, formId);
        newRecord.isInited = false;
        FormDataMgr::GetInstance().SetFormCacheInited(formId, false);
        FormDataMgr::GetInstance().SetNeedAddForm(formId, false);

        // acquire formInfo from provider
        ErrCode errorCode = AcquireProviderFormInfoAsync(formId, info, wantParams);
        if (errorCode != ERR_OK) {
            HILOG_ERROR("AcquireProviderFormInfoAsync failed");
            return errorCode;
        }
    }

    // Add new form user uid.
    FormDataMgr::GetInstance().AddFormUserUid(formId, callingUid);
    if (std::find(newRecord.formUserUids.begin(), newRecord.formUserUids.end(), callingUid) ==
        newRecord.formUserUids.end()) {
        newRecord.formUserUids.emplace_back(callingUid);
    }

    if (hasCacheData) {
        HILOG_INFO("use cache data, formId:%{public}" PRId64 "", formId);
        formInfo.formData = cacheData;
        formInfo.formProviderData.SetDataString(cacheData);
        formInfo.formProviderData.SetImageDataMap(imageDataMap);
    }

    FormDataMgr::GetInstance().CreateFormJsInfo(formId, record, formInfo);

    // start update timer
    ErrCode errorCode = AddFormTimer(newRecord);
    if (errorCode != ERR_OK) {
        return errorCode;
    }
    if (!newRecord.formTempFlag) {
        return FormDbCache::GetInstance().UpdateDBRecord(formId, newRecord);
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::AllotFormBySpecificId(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_DEBUG("start");
    int64_t formId = info.GetFormId();
    FormRecord record;
    bool hasRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    // find in db but not in cache
    FormRecord dbRecord;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbRecord);
    if (getDbRet == ERR_OK || hasRecord) {
        HILOG_DEBUG("The specified ID already exists in the cache or db");
        return AllotFormByInfo(info, callerToken, wantParams, formInfo);
    }
    HILOG_DEBUG("Creates the form with the specified ID");
    return AddNewFormRecord(info, formId, callerToken, wantParams, formInfo);
}

ErrCode FormMgrAdapter::AllotFormByInfo(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    // generate formId
    int64_t newFormId = FormDataMgr::GetInstance().GenerateFormId();
    if (newFormId < 0) {
        HILOG_ERROR("generateFormId no invalid formId");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    UpdateReUpdateFormMap(newFormId);
    HILOG_DEBUG("newFormId:%{public}" PRId64 "", newFormId);
    return AddNewFormRecord(info, newFormId, callerToken, wantParams, formInfo);
}

ErrCode FormMgrAdapter::AddNewFormRecord(const FormItemInfo &info, const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formJsInfo)
{
    HILOG_INFO("call");
    FormItemInfo newInfo(info);
    newInfo.SetFormId(formId);
    // allot form host record
    int callingUid = IPCSkeleton::GetCallingUid();
    if (!FormDataMgr::GetInstance().AllotFormHostRecord(newInfo, callerToken, formId, callingUid)) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // get current userId
    int32_t currentUserId = GetCurrentUserId(callingUid);
    // allot form record
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(newInfo, callingUid, currentUserId);

    FormRenderMgr::GetInstance().RenderForm(formRecord, wantParams, callerToken);

    // acquire formInfo from provider
    ErrCode errorCode = AcquireProviderFormInfoAsync(formId, newInfo, wantParams);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("AcquireProviderFormInfoAsync failed");
        return errorCode;
    }

    // create form info for js
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, formRecord, formJsInfo);

    // storage info
    if (!newInfo.IsTemporaryForm()) {
        errorCode = FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord);
        if (errorCode != ERR_OK) {
            HILOG_ERROR("UpdateDBRecord failed");
            return errorCode;
        }
    }

    // start update timer
    if (info.GetProviderBundleName() != info.GetHostBundleName()) {
        return AddFormTimer(formRecord);
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::AddFormTimer(const FormRecord &formRecord)
{
    if (!formRecord.isEnableUpdate || formRecord.formTempFlag) {
        HILOG_INFO("isEnableUpdate:%{public}d formTempFlag:%{public}d",
            formRecord.isEnableUpdate, formRecord.formTempFlag);
        return ERR_OK;
    }
    HILOG_INFO("start");
    if (formRecord.updateDuration > 0 && !formRecord.isDataProxy) {
        if (!FormDataMgr::GetInstance().HasFormCloudUpdateDuration(formRecord.bundleName)) {
            UpdateFormCloudUpdateDuration(formRecord.bundleName);
        }
        int64_t updateDuration = formRecord.updateDuration;
        if (!GetValidFormUpdateDuration(formRecord.formId, updateDuration)) {
            HILOG_WARN("Get updateDuration failed, uses local configuration");
        }
        bool ret = FormTimerMgr::GetInstance().AddFormTimer(formRecord.formId,
            updateDuration, formRecord.providerUserId);
        return ret ? ERR_OK : ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    if (formRecord.updateAtHour >= 0 && formRecord.updateAtMin >= 0) {
        bool ret = FormTimerMgr::GetInstance().AddFormTimer(formRecord.formId,
            formRecord.updateAtHour, formRecord.updateAtMin, formRecord.providerUserId);
        return ret ? ERR_OK : ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_INFO("no need add form timer");
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleEventNotify(const std::string &providerKey, const std::vector<int64_t> &formIdsByProvider,
    const int32_t formVisibleType)
{
    HILOG_INFO("call");
    size_t position = providerKey.find(Constants::NAME_DELIMITER);
    std::string bundleName = providerKey.substr(0, position);
    std::string abilityName = providerKey.substr(position + strlen(Constants::NAME_DELIMITER));
    sptr<IAbilityConnection> formEventNotifyConnection = new (std::nothrow) FormEventNotifyConnection(formIdsByProvider,
        formVisibleType, bundleName, abilityName);
    if (formEventNotifyConnection == nullptr) {
        HILOG_ERROR("create FormEventNotifyConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(bundleName, abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, formEventNotifyConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

ErrCode FormMgrAdapter::AcquireProviderFormInfoAsync(const int64_t formId,
    const FormItemInfo &info, const WantParams &wantParams)
{
    std::string providerBundleName = info.GetProviderBundleName();
    if (!info.IsEnableForm()) {
        HILOG_INFO("Bundle:%{public}s forbidden", providerBundleName.c_str());
        FormDataMgr::GetInstance().SetRefreshDuringDisableForm(formId, true);

        auto task = [formId, newInfo = info, newWant = wantParams]() {
            FormMgrAdapter::GetInstance().InnerAcquireProviderFormInfoAsync(formId, newInfo, newWant);
        };
        FormRenderMgr::GetInstance().AddAcquireProviderForbiddenTask(info.GetProviderBundleName(), formId, task);
        return ERR_OK;
    }

    if (FormRenderMgr::GetInstance().GetIsVerified()) {
        HILOG_INFO("The authentication status is true");
        return InnerAcquireProviderFormInfoAsync(formId, info, wantParams);
    }

    HILOG_INFO("The currentUser not unlocked");
    auto task = [formId, newInfo = info, newWant = wantParams]() {
        FormMgrAdapter::GetInstance().InnerAcquireProviderFormInfoAsync(formId, newInfo, newWant);
    };
    FormRenderMgr::GetInstance().AddAcquireProviderFormInfoTask(task);
    return ERR_OK;
}

ErrCode FormMgrAdapter::InnerAcquireProviderFormInfoAsync(const int64_t formId,
    const FormItemInfo &info, const WantParams &wantParams)
{
    if (formId <= 0) {
        HILOG_ERROR("formId not greater than 0");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    HILOG_INFO("formId:%{public}" PRId64, formId);

    Want newWant;
    newWant.SetParams(wantParams);
    auto hostToken = newWant.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    sptr<FormAcquireConnection> formAcquireConnection = new (std::nothrow) FormAcquireConnection(formId, info,
        wantParams, hostToken);
    if (formAcquireConnection == nullptr) {
        HILOG_ERROR("null formAcquireConnection");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    Want want;
    want.SetElementName(info.GetProviderBundleName(), info.GetAbilityName());
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formAcquireConnection);
    FormReport::GetInstance().SetStartBindTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    if (errorCode != ERR_OK && errorCode != ERR_ECOLOGICAL_CONTROL_STATUS) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
#ifdef RES_SCHEDULE_ENABLE
    auto&& connectCallback = [](const std::string &bundleName) {
        FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    };
    auto&& disconnectCallback = [](const std::string &bundleName) {
        FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    };
    formAcquireConnection->SetFormAbilityConnectCb(connectCallback);
    formAcquireConnection->SetFormAbilityDisconnectCb(disconnectCallback);
#endif
    return ERR_OK;
}

ErrCode FormMgrAdapter::GetBundleInfo(const AAFwk::Want &want, BundleInfo &bundleInfo, std::string &packageName)
{
    HILOG_DEBUG("GetBundleInfo start");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string deviceId = want.GetElement().GetDeviceID();
    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (bundleName.empty() || abilityName.empty() || moduleName.empty()) {
        HILOG_ERROR("invalid bundleName or abilityName or moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    int32_t currentUserId = GetCurrentUserId(IPCSkeleton::GetCallingUid());
    ErrCode errCode = FormBmsHelper::GetInstance().GetBundleInfoV9(bundleName, currentUserId, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get bundleInfo failed");
        return errCode;
    }

    bool moduleExist = false;
    for (const auto &moduleInfo : bundleInfo.moduleNames) {
        HILOG_DEBUG("bundleInfo.moduleNames, module name:%{public}s", moduleInfo.c_str());
        if (moduleInfo.compare(moduleName) == 0) {
            moduleExist = true;
            break;
        }
    }
    if (!moduleExist) {
        HILOG_ERROR("GetBundleInfo no such module, name:%{public}s", moduleName.c_str());
        return ERR_APPEXECFWK_FORM_NO_SUCH_MODULE;
    }

    packageName = bundleName + moduleName;
    HILOG_DEBUG("GetBundleInfo end");
    return ERR_OK;
}

ErrCode FormMgrAdapter::GetFormInfo(const AAFwk::Want &want, FormInfo &formInfo)
{
    HILOG_DEBUG("GetFormInfo start");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (bundleName.empty() || abilityName.empty() || moduleName.empty()) {
        HILOG_ERROR("invalid bundleName or abilityName or moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormInfo> formInfos {};
    int32_t userId = GetCurrentUserId(IPCSkeleton::GetCallingUid());
    ErrCode errCode = FormInfoMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName,
        formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("GetFormsInfoByModule,get formConfigInfo failed,userId:%{public}d", userId);
        return errCode;
    }

    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    bool abilityExisting = false;
    for (const auto &form : formInfos) {
        if (form.abilityName != abilityName) {
            continue;
        }

        abilityExisting = true;
        if ((formName.empty() && form.defaultFlag) || form.name == formName) {
            formInfo = form;
            formInfo.moduleName = moduleName;
            HILOG_INFO("GetFormInfo end");
            return ERR_OK;
        }
    }

    HILOG_ERROR("fail get form info,abilityName:%{public}s,formName:%{public}s,userId:%{public}d",
        abilityName.c_str(), formName.c_str(), userId);
    return abilityExisting ? ERR_APPEXECFWK_FORM_GET_INFO_FAILED : ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
}

ErrCode FormMgrAdapter::GetFormItemInfo(const AAFwk::Want &want, const BundleInfo &bundleInfo,
    const FormInfo &formInfo, FormItemInfo &formItemInfo)
{
    HILOG_DEBUG("GetFormItemInfo start");
    int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, formInfo.defaultDimension);
    if (!IsDimensionValid(formInfo, dimensionId)) {
        HILOG_ERROR("Invalid dimension");
        return ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION;
    }

    ErrCode ret = CreateFormItemInfo(bundleInfo, formInfo, formItemInfo, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("CreateFormItemInfo failed");
        return ret;
    }
    formItemInfo.SetSpecificationId(dimensionId);
    formItemInfo.SetTemporaryFlag(want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false));
    HILOG_DEBUG("GetFormItemInfo end");
    return ERR_OK;
}

bool FormMgrAdapter::IsDimensionValid(const FormInfo &formInfo, int dimensionId) const
{
    if (formInfo.supportDimensions.empty()) {
        HILOG_ERROR("Js form,no support dimension");
        return false;
    }

    for (size_t i = 0; i < formInfo.supportDimensions.size() && i < Constants::MAX_LAYOUT; i++) {
        if (formInfo.supportDimensions[i] == dimensionId) {
            return true;
        }
    }

    HILOG_ERROR("No matched dimension found for %{public}d", dimensionId);
    return false;
}

ErrCode FormMgrAdapter::CreateFormItemInfo(const BundleInfo &bundleInfo,
    const FormInfo &formInfo, FormItemInfo &itemInfo, const AAFwk::Want &want)
{
    itemInfo.SetProviderBundleName(bundleInfo.name);
    itemInfo.SetVersionCode(bundleInfo.versionCode);
    itemInfo.SetVersionName(bundleInfo.versionName);
    itemInfo.SetCompatibleVersion(bundleInfo.compatibleVersion);
    itemInfo.SetSystemAppFlag(bundleInfo.applicationInfo.isSystemApp);
    itemInfo.SetProviderUid(bundleInfo.applicationInfo.uid);
    itemInfo.SetDescription(formInfo.description);

    std::string hostBundleName;
    bool isSaUid = IPCSkeleton::GetCallingUid() == SYSTEM_UID;
    ErrCode ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    if (isSaUid) {
        hostBundleName = want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_HOST_BUNDLENAME_KEY);
        HILOG_INFO("sa uid call CreateFormItemInfo, hostBundleName:%{public}s", hostBundleName.c_str());
        ret = ERR_OK;
    } else {
        ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    }
    if (ret != ERR_OK) {
        HILOG_ERROR("fail get form config info");
        return ret;
    }
    itemInfo.SetHostBundleName(hostBundleName);
    itemInfo.SetAbilityName(formInfo.abilityName);
    itemInfo.SetModuleName(formInfo.moduleName); // formInfo.moduleName: bundleMgr do not set
    itemInfo.SetFormName(formInfo.name);
    itemInfo.SetEnableUpdateFlag(formInfo.updateEnabled);
    itemInfo.SetUpdateDuration(formInfo.updateDuration);
    itemInfo.SetScheduledUpdateTime(formInfo.scheduledUpdateTime);
    itemInfo.SetJsComponentName(formInfo.jsComponentName);
    itemInfo.SetFormVisibleNotify(formInfo.formVisibleNotify);
    auto formSrc = formInfo.src;
    if (formSrc.rfind(POINT_ETS) == formSrc.size() - POINT_ETS.size()) {
        formSrc.erase(formSrc.end() - POINT_ETS.size(), formSrc.end());
    }
    itemInfo.SetFormSrc(formSrc);
    itemInfo.SetFormWindow(formInfo.window);
    itemInfo.SetType(formInfo.type);
    itemInfo.SetUiSyntax(formInfo.uiSyntax);
    itemInfo.SetIsDynamic(formInfo.isDynamic);
    itemInfo.SetTransparencyEnabled(formInfo.transparencyEnabled);
    itemInfo.SetPrivacyLevel(formInfo.privacyLevel);
    itemInfo.SetDataProxyFlag(formInfo.dataProxyEnabled);
    itemInfo.SetFormBundleType(formInfo.bundleType);

    SetFormItemInfoParams(bundleInfo, formInfo, itemInfo);
    return ERR_OK;
}

void FormMgrAdapter::SetFormItemInfoParams(const BundleInfo& bundleInfo, const FormInfo& formInfo,
    FormItemInfo& itemInfo)
{
    if (!bundleInfo.hapModuleInfos.empty()) {
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            SetFormItemModuleInfo(hapModuleInfo, formInfo, itemInfo);
        }
    }

    HILOG_INFO("size:%{public}zu", bundleInfo.applicationInfo.moduleInfos.size());
    for (const auto &item : bundleInfo.applicationInfo.moduleInfos) {
        HILOG_INFO("moduleName:%{public}s, moduleSourceDir:%{public}s",
            item.moduleName.c_str(), item.moduleSourceDir.c_str());
        if (formInfo.moduleName == item.moduleName) {
            itemInfo.AddHapSourceDirs(item.moduleSourceDir);
        }
    }
}

void FormMgrAdapter::SetFormItemModuleInfo(const HapModuleInfo& hapModuleInfo, const FormInfo& formInfo,
    FormItemInfo& itemInfo)
{
    auto hapPath = hapModuleInfo.hapPath;
    auto moduleName = hapModuleInfo.moduleName;
    HILOG_DEBUG("module [%{public}s] packageName is %{public}s, hap path is %{public}s", moduleName.c_str(),
        hapModuleInfo.packageName.c_str(), hapPath.c_str());
    if (hapPath.find(Constants::ABS_CODE_PATH) != std::string::npos) {
        hapPath = std::regex_replace(hapPath, std::regex(Constants::ABS_CODE_PATH), Constants::LOCAL_BUNDLES);
    }
    nlohmann::json moduleInfos = {
        {Constants::MODULE_PKG_NAME_KEY, hapModuleInfo.packageName},
        {Constants::MODULE_HAP_PATH_KEY, hapPath}
    };
    itemInfo.AddModulePkgName(moduleName, moduleInfos.dump());
    itemInfo.AddModuleInfo(moduleName, hapPath);
    for (const auto &abilityInfo : hapModuleInfo.abilityInfos) {
        if (abilityInfo.name == formInfo.abilityName) {
            itemInfo.SetAbilityModuleName(abilityInfo.moduleName);
            if (!abilityInfo.isModuleJson) {
                itemInfo.SetFormSrc("");
            }
        }
    }
}

int FormMgrAdapter::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_INFO("formId:%{public}" PRId64 ", nextTime:%{public}" PRId64,
        formId, nextTime);
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string bundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(bundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = GetCurrentUserId(callingUid);
    HILOG_INFO("userId:%{public}d, callingUid:%{public}d", userId, callingUid);

    FormRecord formRecord;
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not found in formRecord");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (userId != formRecord.providerUserId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    // check bundleName
    if (bundleName != formRecord.bundleName) {
        HILOG_ERROR("not match bundleName:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    if (formRecord.isDataProxy) {
        HILOG_ERROR("data proxy form not support set next refresh time");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return SetNextRefreshTimeLocked(matchedFormId, nextTime, userId);
}

int FormMgrAdapter::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("Release invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRecord record;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, record)) {
        HILOG_ERROR("no matched form record");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormRenderMgr::GetInstance().ReleaseRenderer(formId, record, compId);
    return ERR_OK;
}

ErrCode FormMgrAdapter::CheckFormBundleName(Want &want, std::string &bundleName,
                                            bool needCheckFormPermission)
{
    if (!GetBundleName(bundleName, needCheckFormPermission)) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (!needCheckFormPermission && bundleName != want.GetBundle()) {
        HILOG_ERROR("not self bundle");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::CheckPublishForm(Want &want, bool needCheckFormPermission)
{
    std::string bundleName;
    ErrCode errCode = CheckFormBundleName(want, bundleName, needCheckFormPermission);
    if (errCode != ERR_OK) {
        return errCode;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (needCheckFormPermission && !IsValidPublishEvent(iBundleMgr, bundleName, want)) {
        HILOG_ERROR("Check valid publish event failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }

    if (want.GetElement().GetBundleName().empty()) {
        HILOG_WARN("emptybundleName.set to currentCallingBundle");
        want.SetBundle(bundleName);
    }

    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (moduleName.empty()) {
        HILOG_ERROR("empty moduleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    bool isTemporary = want.GetBoolParam(AppExecFwk::Constants::PARAM_FORM_TEMPORARY_KEY, false);
    if (isTemporary) {
        HILOG_WARN("The published form should not be temp");
        want.SetParam(AppExecFwk::Constants::PARAM_FORM_TEMPORARY_KEY, false);
    }

    std::string abilityName = want.GetElement().GetAbilityName();
    std::string formName = want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY);
    std::vector<FormInfo> formInfos {};
    errCode = FormInfoMgr::GetInstance()
        .GetFormsInfoByModuleWithoutCheck(want.GetElement().GetBundleName(), moduleName, formInfos);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get forms info");
        return errCode;
    }
    for (auto &formInfo: formInfos) {
        int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
        if ((formInfo.abilityName == abilityName) && (formInfo.name == formName) &&
            (IsDimensionValid(formInfo, dimensionId))) {
            want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
            return ERR_OK;
        }
    }
    HILOG_ERROR("fail find match form info");
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormMgrAdapter::QueryPublishFormToHost(Want &wantToHost)
{
    AppExecFwk::AbilityInfo formAbilityInfo;
    AppExecFwk::ExtensionAbilityInfo formExtensionAbilityInfo;

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = GetCurrentUserId(callingUid);

    // Query the highest priority ability or extension ability for publishing form
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        Constants::FORM_PUBLISH_ACTION, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("fail ImplicitQueryInfoByPriority for publishing form");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("Query highest priority ability failed, no form host ability found");
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }

    if (!abilityInfo.name.empty()) {
        // highest priority ability
        HILOG_DEBUG("Query highest priority ability success. bundleName:%{public}s, ability:%{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        wantToHost.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    } else {
        // highest priority extension ability
        HILOG_DEBUG("Query highest priority extension ability success. bundleName:%{public}s, ability:%{public}s",
            extensionAbilityInfo.bundleName.c_str(), extensionAbilityInfo.name.c_str());
        wantToHost.SetElementName(extensionAbilityInfo.bundleName, extensionAbilityInfo.name);
    }
    return ERR_OK;
}

bool FormMgrAdapter::CheckSnapshotWant(const Want &want)
{
    if (want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY) &&
        want.HasParameter(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY)) {
        std::string snapshot = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY);
        std::string width = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY);
        std::string height = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY);
        std::string screenX = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY);
        std::string screenY = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY);
        HILOG_INFO("SnapshotInfo screenX:%{public}s, screenY:%{public}s, width:%{public}s, height:%{public}s",
            screenX.c_str(), screenY.c_str(), width.c_str(), height.c_str());
        return true;
    } else {
        HILOG_DEBUG("CheckSnapshotWant: want has no component snapshot info");
        return false;
    }
}

ErrCode FormMgrAdapter::RequestPublishFormToHost(Want &want)
{
    Want wantToHost(want);
    ElementName elementName = want.GetElement();
    wantToHost.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, elementName.GetBundleName());
    wantToHost.SetParam(Constants::PARAM_ABILITY_NAME_KEY, elementName.GetAbilityName());
    std::string bundleName = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_BUNDLE_KEY);
    std::string abilityName = want.GetStringParam(Constants::PARAM_PUBLISH_FORM_HOST_ABILITY_KEY);
    wantToHost.SetElementName(bundleName, abilityName);
    wantToHost.SetAction(Constants::FORM_PUBLISH_ACTION);
    CheckSnapshotWant(wantToHost);

    ErrCode errCode = QueryPublishFormToHost(wantToHost);
    if (errCode == ERR_OK) {
        int32_t userId = want.GetIntParam(Constants::PARAM_FORM_USER_ID, -1);
        return FormAmsHelper::GetInstance().StartAbility(wantToHost, userId);
    }

    // Handle by interceptor callback when the system handler is not found.
    if (formPublishInterceptor_ == nullptr) {
        HILOG_ERROR("query publish form failed, and have not publish interceptor. errCode:%{public}d", errCode);
        return errCode;
    }
    int ret = formPublishInterceptor_->ProcessPublishForm(wantToHost);
    if (ret == ERR_OK) {
        HILOG_DEBUG("success to ProcessPublishForm");
    } else {
        HILOG_ERROR("fail ProcessPublishForm");
    }
    return ret;
}

ErrCode FormMgrAdapter::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    HILOG_DEBUG("call");
    ErrCode errCode = CheckPublishForm(want, needCheckFormPermission);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = GetCurrentUserId(callingUid);
    want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    want.SetAction(Constants::FORM_PUBLISH_ACTION);

    // generate formId
    formId = FormDataMgr::GetInstance().GenerateFormId();
    if (formId < 0) {
        HILOG_ERROR("generateFormId no invalid formId");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    {
        std::lock_guard<std::mutex> lock(formResultMutex_);
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            iter->second = AddFormResultErrorCode::UNKNOWN;
        } else {
            formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::UNKNOWN));
        }
    }
    HILOG_DEBUG("formId:%{public}" PRId64 "", formId);
    std::string strFormId = std::to_string(formId);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, strFormId);

    if (withFormBindingData) {
        errCode = FormDataMgr::GetInstance().AddRequestPublishFormInfo(formId, want, formBindingData);
    } else {
        std::unique_ptr<FormProviderData> noFormBindingData = nullptr;
        errCode = FormDataMgr::GetInstance().AddRequestPublishFormInfo(formId, want, noFormBindingData);
    }
    if (errCode != ERR_OK) {
        HILOG_ERROR("add form info error");
        return errCode;
    }
    errCode = RequestPublishFormToHost(want);
    if (errCode != ERR_OK) {
        FormDataMgr::GetInstance().RemoveRequestPublishFormInfo(formId);
        NewFormEventInfo eventInfo;
        FormEventReport::SendFourthFormEvent(FormEventName::INVALID_PUBLISH_FORM_TO_HOST,
            HiSysEventType::STATISTIC, eventInfo, want);
    }

    IncreaseAddFormRequestTimeOutTask(formId);
    if (!formDataProxies.empty()) {
        FormDataProxyMgr::GetInstance().ProduceFormDataProxies(formId, formDataProxies);
    }
    return errCode;
}

ErrCode FormMgrAdapter::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    HILOG_INFO("call");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    std::pair<int64_t, int64_t> eventMsg(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), formId);
    serialQueue_->CancelDelayTask(eventMsg);
    std::lock_guard<std::mutex> lock(formResultMutex_);
    auto iter = formIdMap_.find(formId);
    if (iter != formIdMap_.end()) {
        if (errorCodeInfo.code == Constants::PublishFormErrorCode::SUCCESS) {
            iter->second = AddFormResultErrorCode::SUCCESS;
            errorCodeInfo.message = "set add form success, PublishFormErrorCode is success";
        } else {
            iter->second = AddFormResultErrorCode::FAILED;
            errorCodeInfo.message = "set add form fail, PublishFormErrorCode is not success";
        }
        condition_.notify_all();
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}

ErrCode FormMgrAdapter::AcquireAddFormResult(const int64_t formId)
{
    HILOG_INFO("call");
    auto apiRet = std::make_shared<ErrCode>(ERR_OK);
    std::unique_lock<std::mutex> lock(formResultMutex_);
    condition_.wait(lock, [this, formId, ret = apiRet]() {
        auto iter = formIdMap_.find(formId);
        if (iter != formIdMap_.end()) {
            if (iter->second == AddFormResultErrorCode::SUCCESS) {
                HILOG_INFO("Acquire the result of the success");
                *ret = ERR_OK;
                return true;
            } else if (iter->second == AddFormResultErrorCode::FAILED) {
                HILOG_ERROR("Acquire the result of the failed");
                *ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
                return true;
            } else if (iter->second == AddFormResultErrorCode::TIMEOUT) {
                HILOG_ERROR("Acquire the result of the timeout");
                *ret = ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT;
                return true;
            } else {
                HILOG_INFO("Add form result state is unknown");
                return false;
            }
        }
        HILOG_ERROR("The formid hasn't find");
        *ret = ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        return true;
    });
    return *apiRet;
}

ErrCode FormMgrAdapter::CheckAddRequestPublishForm(const Want &want, const Want &formProviderWant)
{
    std::string bundleName = want.GetElement().GetBundleName();
    std::string bundleNameProvider = formProviderWant.GetElement().GetBundleName();
    if (bundleNameProvider != bundleName) {
        HILOG_ERROR("bundleName not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    std::string moduleNameProvider = formProviderWant.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    if (moduleNameProvider != moduleName) {
        HILOG_ERROR("moduleName not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string abilityName = want.GetElement().GetAbilityName();
    std::string abilityNameProvider = formProviderWant.GetElement().GetAbilityName();
    if (abilityNameProvider != abilityName) {
        HILOG_ERROR("abilityName not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    std::string formNameProvider = formProviderWant.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    if (formNameProvider != formName) {
        HILOG_ERROR("formName not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
    int32_t dimensionIdProvider = formProviderWant.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
    if (dimensionIdProvider != dimensionId) {
        HILOG_ERROR("dimensionId not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    bool isTemporary = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    bool isTemporaryProvider = formProviderWant.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    if (isTemporaryProvider != isTemporary) {
        HILOG_ERROR("temporary not match");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    ErrCode errCode = ERR_OK;
    if (isTemporary) {
        errCode = FormDataMgr::GetInstance().CheckTempEnoughForm();
    } else {
        int32_t currentUserId = GetCurrentUserId(callingUid);
        errCode = FormDataMgr::GetInstance().CheckEnoughForm(callingUid, currentUserId);
    }
    if (errCode != ERR_OK) {
        HILOG_ERROR("too much forms in system");
    }
    return errCode;
}

ErrCode FormMgrAdapter::AddRequestPublishForm(const FormItemInfo &formItemInfo, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo)
{
    HILOG_INFO("call");
    Want formProviderWant;
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    auto formId = formItemInfo.GetFormId();
    ErrCode errCode = FormDataMgr::GetInstance().GetRequestPublishFormInfo(formId, formProviderWant, formProviderData);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get requestPublishForm");
        return errCode;
    }

    errCode = CheckAddRequestPublishForm(want, formProviderWant);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!FormDataMgr::GetInstance().AllotFormHostRecord(formItemInfo, callerToken, formId, callingUid)) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // get current userId
    int32_t currentUserId = GetCurrentUserId(callingUid);
    // allot form record
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(formItemInfo, callingUid, currentUserId);
    if (formProviderData != nullptr) {
        formRecord.formProviderInfo.SetFormData(*formProviderData);
    }
    FormRenderMgr::GetInstance().RenderForm(formRecord, want.GetParams()); // render for arkTs form

    // create form info for js
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, formRecord, formJsInfo);
    FormDataMgr::GetInstance().SetNeedAddForm(formId, true);
    if (formProviderData != nullptr) {
        formJsInfo.formData = formProviderData->GetDataString();
        formJsInfo.formProviderData = *formProviderData;
        if (formProviderData->NeedCache()) {
            HILOG_INFO("data is less than 1k,cache data");
            FormCacheMgr::GetInstance().AddData(formId, formJsInfo.formProviderData);
        }
    }
    // storage info
    if (!formItemInfo.IsTemporaryForm()) {
        if (ErrCode errorCode = FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord);
            errorCode != ERR_OK) {
            HILOG_ERROR("UpdateDBRecord failed");
            return errorCode;
        }
    }
    std::vector<FormDataProxy> formDataProxies;
    if (FormDataProxyMgr::GetInstance().ConsumeFormDataProxies(formId, formDataProxies)) {
        FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want);
    }
    // start update timer
    return AddFormTimer(formRecord);
}

bool FormMgrAdapter::GetBundleName(std::string &bundleName, bool needCheckFormPermission)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return false;
    }

    int uid = IPCSkeleton::GetCallingUid();
    if (needCheckFormPermission && !IN_PROCESS_CALL(iBundleMgr->CheckIsSystemAppByUid(uid))) {
        HILOG_ERROR("form not systemApp.uid:%{public}d", uid);
        return false;
    }

    int32_t result = IN_PROCESS_CALL(iBundleMgr->GetNameForUid(uid, bundleName));
    if (result != ERR_OK || bundleName.empty()) {
        HILOG_ERROR("not get bundleName by uid:%{public}d", uid);
        return false;
    }
    return true;
}

int FormMgrAdapter::SetNextRefreshTimeLocked(const int64_t formId, const int64_t nextTime, const int32_t userId)
{
    HILOG_ERROR("SetNextRefreshTimeLocked");
    int32_t timerRefreshedCount = FormTimerMgr::GetInstance().GetRefreshCount(formId);
    if (timerRefreshedCount >= Constants::LIMIT_COUNT) {
        HILOG_ERROR("already refresh times:%{public}d", timerRefreshedCount);
        FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_HIGH_FREQUENCY);
        FormTimerMgr::GetInstance().MarkRemind(formId);
        return ERR_APPEXECFWK_FORM_MAX_REFRESH;
    }

    if (!FormTimerMgr::GetInstance().SetNextRefreshTime(formId, nextTime * Constants::SEC_PER_MIN, userId)) {
        HILOG_ERROR("fail");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}

bool FormMgrAdapter::IsUpdateValid(const int64_t formId, const std::string &bundleName)
{
    if (formId <= 0 || bundleName.empty()) {
        return false;
    }
    return true;
}

int FormMgrAdapter::EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("enableUpdateForm");
    return HandleUpdateFormFlag(formIDs, callerToken, true, false);
}

int FormMgrAdapter::DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("disableUpdateForm");
    return HandleUpdateFormFlag(formIDs, callerToken, false, false);
}

int FormMgrAdapter::MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!want.HasParameter(Constants::PARAM_MESSAGE_KEY)) {
        HILOG_ERROR("messageInfo not exist");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord formHostRecord;
    bool isHostExist = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, formHostRecord);
    if (!isHostExist) {
        HILOG_ERROR("cannot find target client");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!formHostRecord.Contains(matchedFormId)) {
        HILOG_ERROR("form not self-owned");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    auto errCode = FormProviderMgr::GetInstance().MessageEvent(matchedFormId, record, want);
    if (errCode != ERR_OK) {
        return errCode;
    }
    HILOG_INFO("find target client");

    NotifyFormClickEvent(formId, FORM_CLICK_MESSAGE);
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    if (!FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        int callingUid = IPCSkeleton::GetCallingUid();
        int32_t userId = GetCurrentUserId(callingUid);
        DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
            record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_CLICKED);
        DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, userId);
    }
#endif
    return ERR_OK;
}

int FormMgrAdapter::RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId or bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (formId < MAX_NUMBER_OF_JS) {
        want.SetParam(Constants::PARAM_FORM_ID, formId);
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, formId);
    } else {
        want.SetParam(Constants::PARAM_FORM_ID, std::to_string(formId));
        want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formId));
    }

    want.SetParam(Constants::PARAM_APP_CLONE_INDEX_KEY, 0);

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (record.bundleName != want.GetBundle() && want.GetUriString().empty()) {
        if (!record.isSystemApp) {
            HILOG_WARN("Only system apps can launch the ability of the other apps");
            want.SetBundle(record.bundleName);
        }
    }
    if (FormRouterProxyMgr::GetInstance().HasRouterProxy(formId)) {
        HILOG_INFO("Router proxy was setted sucessful");
        FormRouterProxyMgr::GetInstance().OnFormRouterEvent(formId, want);
        return ERR_OK;
    }
    ApplicationInfo appInfo;
    int32_t result;
    if (FormBmsHelper::GetInstance().GetApplicationInfo(record.bundleName, FormUtil::GetCurrentAccountId(),
        appInfo) != ERR_OK) {
        HILOG_ERROR("Get app info failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    if (!want.GetUriString().empty()) {
        HILOG_INFO("Router by uri");
        int32_t result = IN_PROCESS_CALL(FormAmsHelper::GetInstance().GetAbilityManager()->StartAbilityOnlyUIAbility(
            want, callerToken, appInfo.accessTokenId));
        if (result != ERR_OK && result != START_ABILITY_WAITING) {
            HILOG_ERROR("fail StartAbility, result:%{public}d", result);
            return result;
        }
        NotifyFormClickEvent(formId, FORM_CLICK_ROUTER);
        return ERR_OK;
    }

    result = IN_PROCESS_CALL(FormAmsHelper::GetInstance().GetAbilityManager()->StartAbilityOnlyUIAbility(
        want, callerToken, appInfo.accessTokenId));
    if (result != ERR_OK && result != START_ABILITY_WAITING) {
        HILOG_ERROR("fail StartAbility, result:%{public}d", result);
        return result;
    }

    NotifyFormClickEvent(formId, FORM_CLICK_ROUTER);
#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    if (!FormDataMgr::GetInstance().ExistTempForm(matchedFormId)) {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        int32_t userId = GetCurrentUserId(callingUid);
        DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
            record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_CLICKED);
        DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, userId);
    }
#endif
    return ERR_OK;
}

int FormMgrAdapter::BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    if (formId <= 0) {
        HILOG_ERROR("invalid formId or bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord record;
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    if (want.GetBundle().empty() || record.bundleName != want.GetBundle()) {
        HILOG_DEBUG("The parameter contains the wrong bundleName or the empty bundleName");
        want.SetBundle(record.bundleName);
    }
    if (!CheckKeepBackgroundRunningPermission(iBundleMgr, record.bundleName)) {
        HILOG_ERROR("The app does not have permission for keeping background running");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    std::string params = want.GetStringParam(Constants::FORM_CALL_EVENT_PARAMS);
    nlohmann::json jsonObject = nlohmann::json::parse(params, nullptr, false);
    if (jsonObject.is_discarded()) {
        HILOG_ERROR("fail parse jsonDataString:%{public}s", params.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (!jsonObject.contains(Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY) ||
        !jsonObject.at(Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY).is_string()) {
        HILOG_ERROR("fail get method from params");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<IAbilityConnection> formBackgroundConnection = new (std::nothrow) FormBackgroundConnection(
        formId, want.GetBundle(), want.GetElement().GetAbilityName(),
        jsonObject[Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY].get<std::string>(), params);
    if (formBackgroundConnection == nullptr) {
        HILOG_ERROR("null formBackgroundConnection");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    want.SetParam(Constants::PARAM_FORM_ID, formId);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, formId);
    int32_t result = IN_PROCESS_CALL(FormAmsHelper::GetInstance().GetAbilityManager()->StartAbilityByCall(want,
        formBackgroundConnection, callerToken));
    if (result != ERR_OK) {
        HILOG_ERROR("fail StartAbilityByCall, result:%{public}d", result);
        return result;
    }
    NotifyFormClickEvent(formId, FORM_CLICK_CALL);
    return ERR_OK;
}

ErrCode FormMgrAdapter::HandleUpdateFormFlag(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate)
{
    HILOG_DEBUG("call");
    if (formIds.empty() || callerToken == nullptr) {
        HILOG_ERROR("invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::vector<int64_t> refreshForms;
    int errCode = FormDataMgr::GetInstance().UpdateHostFormFlag(formIds, callerToken,
        flag, isOnlyEnableUpdate, refreshForms);
    if (errCode == ERR_OK && !refreshForms.empty()) {
        int32_t userId = FormUtil::GetCurrentAccountId();
        for (const int64_t id : refreshForms) {
            HILOG_DEBUG("formRecord need refresh:%{public}" PRId64 "", id);
            Want want;
            want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
            FormProviderMgr::GetInstance().RefreshForm(id, want, false);
        }
    }
    return errCode;
}

bool FormMgrAdapter::IsFormCached(const FormRecord record)
{
    if (record.versionUpgrade) {
        return false;
    }
    return true;
}

void FormMgrAdapter::AcquireProviderFormInfo(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }
    FormRecord formRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, formRecord, formJsInfo);
    int error = formProviderProxy->AcquireProviderFormInfo(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("fail acquire providerFormInfo");
    }
    FormReport::GetInstance().SetEndGetTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
}

void FormMgrAdapter::NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        HILOG_ERROR("get formProviderProxy failed");
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        return;
    }
    int error = formProviderProxy->NotifyFormDelete(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        HILOG_ERROR("fail NotifyFormDelete");
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
    }
}

bool FormMgrAdapter::CreateHandleEventMap(const int64_t matchedFormId, const FormRecord &formRecord,
    std::map<std::string, std::vector<int64_t>> &eventMaps)
{
    if (!formRecord.formVisibleNotify) {
        HILOG_WARN("the config 'formVisibleNotify' is false, formId:%{public}" PRId64 ".",
            matchedFormId);
        return false;
    }

    std::string providerKey = formRecord.bundleName + Constants::NAME_DELIMITER + formRecord.abilityName;
    auto iter = eventMaps.find(providerKey);
    if (iter == eventMaps.end()) {
        std::vector<int64_t> formEventsByProvider {matchedFormId};
        eventMaps.insert(std::make_pair(providerKey, formEventsByProvider));
    } else {
        iter->second.emplace_back(matchedFormId);
    }
    return true;
}

bool FormMgrAdapter::isFormShouldUpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
    const sptr<IRemoteObject> &callerToken, FormRecord &formRecord)
{
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_WARN("not exist such form, formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }

    if (formRecord.providerUserId != userId) {
        HILOG_WARN("not self form, formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }
    FormHostRecord formHostRecord;
    bool hasFormHostRecord = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, formHostRecord);
    if (!(hasFormHostRecord && formHostRecord.Contains(matchedFormId))) {
        HILOG_WARN("form not belong to self,formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }
    return true;
}

bool FormMgrAdapter::UpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
    const sptr<IRemoteObject> &callerToken, const int32_t &formVisibleType, FormRecord &formRecord)
{
    formRecord.formVisibleNotifyState = formVisibleType;
    formRecord.isNeedNotify = true;
    if (!FormDataMgr::GetInstance().UpdateFormRecord(matchedFormId, formRecord)) {
        HILOG_WARN("set formVisibleNotifyState error,formId:%{public}" PRId64 ".",
            matchedFormId);
        return false;
    }

    HILOG_INFO("formId:%{public}" PRId64 ", needRefresh:%{public}d, formVisibleType:%{public}d,"
        "isTimerRefresh:%{public}d", matchedFormId, formRecord.needRefresh,
        static_cast<int32_t>(formVisibleType), formRecord.isTimerRefresh);
    // If the form need refresh flag is true and form visibleType is FORM_VISIBLE, refresh the form host.
    if (formRecord.needRefresh && formVisibleType == Constants::FORM_VISIBLE) {
        if (formRecord.isTimerRefresh) {
            FormTimerMgr::GetInstance().RefreshWhenFormVisible(formRecord.formId, userId);
        } else {
            std::string cacheData;
            std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
            FormHostRecord formHostRecord;
            (void)FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, formHostRecord);
            // If the form has business cache, refresh the form host.
            if (FormCacheMgr::GetInstance().GetData(matchedFormId, cacheData, imageDataMap)) {
                formRecord.formProviderInfo.SetFormDataString(cacheData);
                formRecord.formProviderInfo.SetImageDataMap(imageDataMap);
                formHostRecord.OnUpdate(matchedFormId, formRecord);
            }
        }
    }
    return true;
}

bool FormMgrAdapter::CheckIsSystemAppByBundleName(const sptr<IBundleMgr> &iBundleMgr,
    const int32_t &userId, const std::string &bundleName)
{
    AppExecFwk::ApplicationInfo appInfo;
    if (IN_PROCESS_CALL(iBundleMgr->GetApplicationInfoV9(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
        userId, appInfo)) != ERR_OK) {
        HILOG_ERROR("get ApplicationInfo failed");
        return false;
    }

    HILOG_DEBUG("bundle:%{public}s. isSystemApp=%{public}d", bundleName.c_str(), appInfo.isSystemApp);
    return appInfo.isSystemApp;
}

bool FormMgrAdapter::IsValidPublishEvent(const sptr<IBundleMgr> &iBundleMgr,
    const std::string &bundleName, const Want &want, bool needCheckFormPermission)
{
    int32_t userId = FormUtil::GetCurrentAccountId();
    if (needCheckFormPermission && !CheckIsSystemAppByBundleName(iBundleMgr, userId, bundleName)) {
        HILOG_ERROR("Only system app can request publish form");
        return false;
    }
    std::vector<Want> wants{want};
    return IsErmsSupportPublishForm(bundleName, wants);
}

bool FormMgrAdapter::CheckKeepBackgroundRunningPermission(const sptr<IBundleMgr> &iBundleMgr,
    const std::string &bundleName)
{
    BundleInfo bundleInfo;
    if (FormBmsHelper::GetInstance().GetBundleInfoWithPermission(bundleName,
        FormUtil::GetCurrentAccountId(), bundleInfo)) {
        HILOG_DEBUG("get bundleInfo success");
        auto item = find(bundleInfo.reqPermissions.begin(), bundleInfo.reqPermissions.end(),
            Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);
        if (item == bundleInfo.reqPermissions.end()) {
            return false;
        }
    } else {
        HILOG_WARN("can't get bundleInfo's uid");
        return false;
    }

    return true;
}

int32_t FormMgrAdapter::GetCurrentUserId(const int callingUid)
{
    // get current userId
    int32_t userId = callingUid / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    return userId;
}

int FormMgrAdapter::DeleteInvalidForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    HILOG_INFO("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::set<int64_t> matchedFormIds {};
    for (int64_t formId : formIds) {
        int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        matchedFormIds.emplace(matchedFormId);
        HILOG_INFO("valid formId, formId:%{public}" PRId64, formId);
    }
    std::map<int64_t, bool> removedFormsMap {};
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCurrentAccountId();

    // delete invalid DB form record
    FormDbCache::GetInstance().DeleteInvalidDBForms(userId, callingUid, matchedFormIds, removedFormsMap);
    // delete invalid temp form record
    FormDataMgr::GetInstance().DeleteInvalidTempForms(userId, callingUid, matchedFormIds, removedFormsMap);

    if (!removedFormsMap.empty()) {
        FormDataMgr::GetInstance().ClearHostDataByInvalidForms(callingUid, removedFormsMap);
        // delete forms timer
        for (const auto &removedForm : removedFormsMap) {
            if (removedForm.second) {
                FormTimerMgr::GetInstance().RemoveFormTimer(removedForm.first);
                FormRenderMgr::GetInstance().DeleteAcquireForbiddenTaskByFormId(removedForm.first);
            }
        }
    }

    std::string bundleName;
    if (GetBundleName(bundleName)) {
        // delete invalid publish form data
        FormDataMgr::GetInstance().DeleteInvalidPublishForms(userId, bundleName, matchedFormIds);
    }

    numFormsDeleted = static_cast<int32_t>(removedFormsMap.size());
    HILOG_INFO("done,%{public}d forms deleted", numFormsDeleted);
    return ERR_OK;
}

ErrCode FormMgrAdapter::AcquireFormStateCheck(const std::string &bundleName,
    const std::string &abilityName, const Want &want, std::string &provider)
{
    if (bundleName.empty() || abilityName.empty()) {
        HILOG_ERROR("empty bundleName or abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::string moduleName = want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY);
    std::string formName = want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY);
    int32_t dimensionId = want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 1);

    if (moduleName.empty() || formName.empty()) {
        HILOG_ERROR("empty moduleName or formName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormInfo> formInfos {};
    ErrCode errCode = FormInfoMgr::GetInstance()
        .GetFormsInfoByModuleWithoutCheck(want.GetElement().GetBundleName(), moduleName, formInfos);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get forms info");
        return errCode;
    }

    bool found = false;
    for (auto &formInfo : formInfos) {
        if ((formInfo.abilityName == abilityName) && (formInfo.name == formName) &&
            (IsDimensionValid(formInfo, dimensionId))) {
            found = true;
            HILOG_INFO("form info found");
            break;
        }
    }
    if (!found) {
        HILOG_INFO("find matchFormInfo failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    const std::string doubleColon = "::";
    provider.append(bundleName).append(doubleColon).append(abilityName).append(doubleColon)
        .append(moduleName).append(doubleColon).append(formName).append(doubleColon)
        .append(std::to_string(dimensionId)).append(doubleColon).append(std::to_string(callingUid));
    return ERR_OK;
}

int FormMgrAdapter::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
    FormStateInfo &stateInfo)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();

    std::string provider;
    ErrCode errCode = AcquireFormStateCheck(bundleName, abilityName, want, provider);
    if (errCode != ERR_OK) {
        return errCode;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    FormItemInfo info;
    FormDataMgr::GetInstance().CreateFormStateRecord(provider, info, callerToken, callingUid);

    HILOG_DEBUG("bundleName:%{public}s, abilityName:%{public}s", bundleName.c_str(), abilityName.c_str());
    sptr<IAbilityConnection> connection =
        new (std::nothrow) FormAcquireStateConnection(bundleName, abilityName, want, provider);
    if (connection == nullptr) {
        HILOG_ERROR("create FormAcquireStateConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want targetWant;
    targetWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    targetWant.SetElementName(bundleName, abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(targetWant, connection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    stateInfo.state = FormState::DEFAULT;
    return ERR_OK;
}

int FormMgrAdapter::AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
    AAFwk::WantParams &formData)
{
    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form info get formRecord failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    std::string bundleName = formRecord.bundleName;
    std::string abilityName = formRecord.abilityName;

    HILOG_DEBUG("bundleName:%{public}s, abilityName:%{public}s", bundleName.c_str(), abilityName.c_str());
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    FormItemInfo info;
    FormDataMgr::GetInstance().CreateFormAcquireDataRecord(requestCode, info, callerToken, callingUid);
    sptr<IAbilityConnection> connection =
        new (std::nothrow) FormAcquireDataConnection(formId, bundleName, abilityName, requestCode);
    if (connection == nullptr) {
        HILOG_ERROR("create FormAcquireDataConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want targetWant;
    targetWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    targetWant.SetElementName(bundleName, abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(targetWant, connection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

int FormMgrAdapter::NotifyFormsVisible(const std::vector<int64_t> &formIds,
    bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("isVisible:%{public}d", isVisible);
    return FormDataMgr::GetInstance().NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrAdapter::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds,
    bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("isEnableUpdate:%{public}d", isEnableUpdate);
    return HandleUpdateFormFlag(formIds, callerToken, isEnableUpdate, true);
}

int FormMgrAdapter::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormInfoMgr::GetInstance().GetAllFormsInfo(formInfos);
}

int FormMgrAdapter::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormInfoMgr::GetInstance().GetFormsInfoByBundle(bundleName, formInfos);
}

int FormMgrAdapter::GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormInfoMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
}

int FormMgrAdapter::GetFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormInfoMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

bool FormMgrAdapter::IsRequestPublishFormSupported()
{
    /* Query the highest priority ability or extension ability for publishing form */
    std::string bundleName;
    if (!GetBundleName(bundleName)) {
        HILOG_ERROR("get BundleName failed");
        return false;
    }

    std::vector<Want> wants;
    bool isSupport = IsErmsSupportPublishForm(bundleName, wants);
    if (!isSupport) {
        HILOG_ERROR("Erms not support to publish forms");
        return false;
    }

    if (formPublishInterceptor_ != nullptr) {
        HILOG_DEBUG("query publish form has publish interceptor, return true");
        return true;
    }

    auto action = Constants::FORM_PUBLISH_ACTION;
    auto userId = GetCurrentUserId(IPCSkeleton::GetCallingUid());
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(action, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("fail ImplicitQueryInfoByPriority for publishing form");
        return false;
    }

    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("Query highest priority ability failed, no form host ability found");
        return false;
    }
    return true;
}

bool FormMgrAdapter::checkFormHostHasSaUid(const FormRecord &formRecord)
{
    return std::find(formRecord.formUserUids.begin(), formRecord.formUserUids.end(),
        SYSTEM_UID) != formRecord.formUserUids.end();
}

ErrCode FormMgrAdapter::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormObserverRecord::GetInstance().SetFormAddObserver(bundleName, callerToken);
}

ErrCode FormMgrAdapter::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormObserverRecord::GetInstance().SetFormRemoveObserver(bundleName, callerToken);
}

int32_t FormMgrAdapter::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_DEBUG("isTempFormFlag:%{public}d", isTempFormFlag);
    if (isTempFormFlag) {
        return FormDataMgr::GetInstance().GetTempFormsCount(formCount);
    }
    return FormDataMgr::GetInstance().GetCastFormsCount(formCount);
}

int32_t FormMgrAdapter::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_DEBUG("bundleName:%{public}s", bundleName.c_str());
    return FormDataMgr::GetInstance().GetHostFormsCount(bundleName, formCount);
}

ErrCode FormMgrAdapter::GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormDataMgr::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrAdapter::GetRunningFormInfosByBundleName(
    const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    return FormDataMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrAdapter::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    return FormDataMgr::GetInstance().GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgrAdapter::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    return FormDataMgr::GetInstance().GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgrAdapter::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
{
    return FormDataMgr::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgrAdapter::RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formObserversMutex_);
    auto formObserver = formObservers_.find(bundleName);
    if (formObserver == formObservers_.end()) {
        HILOG_DEBUG("%{public}s start register", bundleName.c_str());
        std::vector<sptr<IRemoteObject>> remoteObjects;
        remoteObjects.emplace_back(callerToken);
        formObservers_.emplace(bundleName, remoteObjects);
    } else {
        auto &remoteObjects = formObserver->second;
        auto itr = std::find(remoteObjects.begin(), remoteObjects.end(), callerToken);
        if (itr != remoteObjects.end()) {
            HILOG_ERROR("callback is already exist");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        HILOG_DEBUG("%{public}s add register.", bundleName.c_str());
        remoteObjects.emplace_back(callerToken);
    }
    SetDeathRecipient(callerToken, new (std::nothrow) FormMgrAdapter::ClientDeathRecipient());
    HILOG_DEBUG("success");
    return ERR_OK;
}

ErrCode FormMgrAdapter::RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formObserversMutex_);
    auto formObserver = formObservers_.find(bundleName);
    if (formObserver == formObservers_.end()) {
        HILOG_ERROR("bundleName not exist");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    } else {
        auto &remoteObjects = formObserver->second;
        for (auto itr = remoteObjects.begin(); itr != remoteObjects.end();) {
            if (*itr == callerToken) {
                remoteObjects.erase(itr);
                SetDeathRecipient(callerToken, new (std::nothrow) FormMgrAdapter::ClientDeathRecipient());
                HILOG_DEBUG("success");
                return ERR_OK;
            }
            ++itr;
        }
    }
    HILOG_ERROR("callback not exist");
    return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
}

ErrCode FormMgrAdapter::RegisterFormRouterProxy(
    const std::vector<int64_t>& formIds, const sptr<IRemoteObject>& callerToken)
{
    HILOG_DEBUG("call");
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<int64_t> matchedFormIds {};
    std::vector<int64_t> hostOwnFormIds {};
    auto uid = IPCSkeleton::GetCallingUid();
    FormRecord record;
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("FormId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        auto matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_ERROR("No matching formRecord was found for the formId:%{public}" PRId64 "", formId);
            continue;
        }
        matchedFormIds.push_back(formId);

        if (record.providerUserId != FormUtil::GetCurrentAccountId()) {
            // Checks for cross-user operations.
            HILOG_ERROR("The formId:%{public}" PRId64
                        " corresponds to a card that is not for the currently active user.",
                formId);
            continue;
        } else if (std::find(record.formUserUids.begin(),
            record.formUserUids.end(), uid) == record.formUserUids.end()) {
            // Checks for cross-host operations
            HILOG_ERROR("The formId:%{public}" PRId64 " owned by other formHost", formId);
            continue;
        } else {
            HILOG_DEBUG("The setup was sucessful, matchedFormIds:%{public}" PRId64 "", formId);
            hostOwnFormIds.push_back(formId);
        }
    }
    if (matchedFormIds.empty()) {
        HILOG_ERROR("invalid formIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (hostOwnFormIds.empty()) {
        HILOG_ERROR("All formIds was not setted by self");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    return FormRouterProxyMgr::GetInstance().SetFormRouterProxy(hostOwnFormIds, callerToken);
}

ErrCode FormMgrAdapter::UnregisterFormRouterProxy(const std::vector<int64_t>& formIds)
{
    HILOG_DEBUG("call");
    std::vector<int64_t> matchedFormIds {};
    std::vector<int64_t> hostOwnFormIds {};
    auto uid = IPCSkeleton::GetCallingUid();
    FormRecord record;
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("FormId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        auto matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_ERROR("No matching formRecord was found for the formId:%{public}" PRId64 "", formId);
            continue;
        }
        matchedFormIds.push_back(formId);

        if (record.providerUserId != FormUtil::GetCurrentAccountId()) {
            // Checks for cross-user operations.
            HILOG_ERROR("The formId:%{public}" PRId64
                        " corresponds to a card that is not for the currently active user.",
                formId);
            continue;
        } else if (std::find(record.formUserUids.begin(),
            record.formUserUids.end(), uid) == record.formUserUids.end()) {
            // Checks for cross-host operations
            HILOG_ERROR("The formId:%{public}" PRId64 " owned by other formHost", formId);
            continue;
        } else {
            HILOG_DEBUG("The setup was sucessful, matchedFormIds:%{public}" PRId64 "", formId);
            hostOwnFormIds.push_back(formId);
        }
    }
    if (matchedFormIds.empty()) {
        HILOG_ERROR("invalid formIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (hostOwnFormIds.empty()) {
        HILOG_ERROR("All formIds was not setted by self");
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    return FormRouterProxyMgr::GetInstance().RemoveFormRouterProxy(hostOwnFormIds);
}

void FormMgrAdapter::SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    HILOG_DEBUG("call");
    if (callerToken == nullptr || deathRecipient == nullptr) {
        HILOG_ERROR("empty callerToken or deathRecipient");
        return;
    }
    std::lock_guard<std::mutex> lock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(callerToken);
    if (iter == deathRecipients_.end()) {
        deathRecipients_.emplace(callerToken, deathRecipient);
        callerToken->AddDeathRecipient(deathRecipient);
    } else {
        HILOG_DEBUG("The deathRecipient has been added");
    }
}

void FormMgrAdapter::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("call");

    // Clean the formObservers_.
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("null remoteObject");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(formObserversMutex_);
        for (auto it = formObservers_.begin(); it != formObservers_.end();) {
            auto &remoteObjects = it->second;
            for (auto iter = remoteObjects.begin(); iter != remoteObjects.end();) {
                if (*iter == object) {
                    iter = remoteObjects.erase(iter);
                    continue;
                }
                ++iter;
            }
            if (remoteObjects.empty()) {
                it = formObservers_.erase(it);
                continue;
            }
            ++it;
        }
    }
    std::lock_guard<std::mutex> deathLock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(object);
    if (iter != deathRecipients_.end()) {
        auto deathRecipient = iter->second;
        deathRecipients_.erase(iter);
        object->RemoveDeathRecipient(deathRecipient);
    }
}

void FormMgrAdapter::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("remote died");
    FormMgrAdapter::GetInstance().CleanResource(remote);
}

int32_t FormMgrAdapter::RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    if (interceptorCallback == nullptr) {
        HILOG_ERROR("null interceptorCallback");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    if (interceptor == nullptr) {
        HILOG_ERROR("RegisterPublishFormInterceptor failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    formPublishInterceptor_ = interceptor;
    return ERR_OK;
}

int32_t FormMgrAdapter::UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_DEBUG("call");
    if (interceptorCallback == nullptr) {
        HILOG_ERROR("null interceptorCallback");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    if (interceptor == nullptr) {
        HILOG_ERROR("UnregisterPublishFormInterceptor failed");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formPublishInterceptor_ == interceptor) {
        HILOG_DEBUG("UnregisterPublishFormInterceptor success");
        formPublishInterceptor_ = nullptr;
        return ERR_OK;
    }
    HILOG_ERROR("the param not equal to the current interceptor");
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormMgrAdapter::RegisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("null CallerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormObserverRecord::GetInstance().SetFormEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgrAdapter::UnregisterClickEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_DEBUG("call");
    if (observer == nullptr) {
        HILOG_ERROR("null CallerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return FormObserverRecord::GetInstance().RemoveFormEventObserver(bundleName, formEventType, observer);
}

void FormMgrAdapter::NotifyFormClickEvent(int64_t formId, const std::string &formClickType)
{
    HILOG_DEBUG("call");
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);

    RunningFormInfo runningFormInfo;
    auto ref = FormDataMgr::GetInstance().GetRunningFormInfosByFormId(matchedFormId, runningFormInfo);
    if (ref != ERR_OK) {
        HILOG_ERROR("Get Running info error");
        return;
    }

    FormObserverRecord::GetInstance().HandleFormEvent(runningFormInfo.hostBundleName, formClickType, runningFormInfo);
    // The application layer can pass in an empty Bundlename,
    // Which represents listening to a certain event of all applications
    FormObserverRecord::GetInstance().HandleFormEvent(EMPTY_BUNDLE, formClickType, runningFormInfo);
}

bool FormMgrAdapter::GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const
{
    HILOG_DEBUG("call");
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return false;
    }

    ApplicationInfo appInfo;
    if (FormBmsHelper::GetInstance().GetApplicationInfo(formRecord.bundleName, FormUtil::GetCurrentAccountId(),
        appInfo) != ERR_OK) {
        HILOG_ERROR("Get app info failed");
        return false;
    }

    if (appInfo.apiTargetVersion < API_11) {
        HILOG_INFO("API version is lower than 11, uses local configuration");
        updateDuration = formRecord.updateDuration;
        return true;
    }

    int duration = FormDataMgr::GetInstance().GetFormCloudUpdateDuration(formRecord.bundleName);
    if (duration == 0) {
        HILOG_INFO("No valid cloud update duration, uses local configuration");
        updateDuration = formRecord.updateDuration;
        return true;
    }
    int64_t cloudsDuration = duration * Constants::TIME_CONVERSION;
    updateDuration = std::max(formRecord.updateDuration, cloudsDuration);
    return true;
}

void FormMgrAdapter::UpdateFormCloudUpdateDuration(const std::string &bundleName)
{
    HILOG_DEBUG("call");
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        FormDataMgr::GetInstance().RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    std::string additionalInfo;
    if (IN_PROCESS_CALL(iBundleMgr->GetAdditionalInfo(bundleName, additionalInfo)) != ERR_OK) {
        HILOG_ERROR("fail get additionalInfo");
        FormDataMgr::GetInstance().RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    if (additionalInfo.empty()) {
        HILOG_INFO("empty AdditionalInfo");
        FormDataMgr::GetInstance().RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    std::regex regex(R"(formUpdateLevel:(\d+))");
    std::smatch searchResult;
    std::string::const_iterator iterStart = additionalInfo.begin();
    std::string::const_iterator iterEnd = additionalInfo.end();
    std::vector<int> durationArray;
    while (std::regex_search(iterStart, iterEnd, searchResult, regex)) {
        iterStart = searchResult[0].second;
        if (searchResult[DATA_FIELD].str().length() > FORM_UPDATE_LEVEL_VALUE_MAX_LENGTH) {
            continue;
        }
        int val = std::stoi(searchResult[DATA_FIELD].str());
        if (val >= Constants::MIN_CONFIG_DURATION && val <= Constants::MAX_CONFIG_DURATION) {
            durationArray.emplace_back(val);
        }
    }

    if (durationArray.empty()) {
        HILOG_INFO("No valid formUpdateLevel in additionalInfo");
        FormDataMgr::GetInstance().RemoveFormCloudUpdateDuration(bundleName);
        return;
    }

    FormDataMgr::GetInstance().UpdateFormCloudUpdateDuration(bundleName, durationArray.back());
}

int32_t FormMgrAdapter::GetCallerType(std::string bundleName)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    AppExecFwk::ApplicationInfo callerAppInfo;
    auto flag = AppExecFwk::ApplicationFlag::GET_BASIC_APPLICATION_INFO;
    auto userId = GetCurrentUserId(IPCSkeleton::GetCallingUid());
    bool getCallerResult = IN_PROCESS_CALL(iBundleMgr->GetApplicationInfo(bundleName, flag, userId, callerAppInfo));
    if (!getCallerResult) {
        HILOG_ERROR("Get callerAppInfo failed");
        return FormErmsCallerInfo::TYPE_INVALID;
    }

    switch (callerAppInfo.bundleType) {
        case AppExecFwk::BundleType::ATOMIC_SERVICE:
            return FormErmsCallerInfo::TYPE_ATOM_SERVICE;
        case AppExecFwk::BundleType::APP:
            return FormErmsCallerInfo::TYPE_HARMONY_APP;
        default:
            HILOG_WARN("the caller type is not harmony app or atom service:%{public}d", callerAppInfo.bundleType);
            break;
    }
    return FormErmsCallerInfo::TYPE_INVALID;
}

bool FormMgrAdapter::IsErmsSupportPublishForm(std::string bundleName, std::vector<Want> wants)
{
    bool isSupport = true;
    std::string supportErms = OHOS::system::GetParameter(FORM_SUPPORT_ECOLOGICAL_RULEMGRSERVICE, "true");
    if (supportErms == "false") {
        HILOG_ERROR("fms not support Erms between applications");
        return true;
    }
    FormErmsCallerInfo callerInfo;
    callerInfo.packageName = bundleName;
    callerInfo.uid = IPCSkeleton::GetCallingUid();
    callerInfo.pid = IPCSkeleton::GetCallingPid();
    callerInfo.callerAppType = GetCallerType(bundleName);

    int32_t ret = FormEcologicalRuleClient::GetInstance().IsSupportPublishForm(wants, callerInfo, isSupport);
    if (ret != ERR_OK) {
        HILOG_ERROR("call IsSupportPublishForm failed:%{public}d, default is support.", ret);
        return true;
    }
    return isSupport;
}

bool FormMgrAdapter::IsFormRenderServiceCall(int callingUid)
{
    std::string callBundleName = "";
    auto ret = FormBmsHelper::GetInstance().GetBundleNameByUid(callingUid, callBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get bundleName by uid failed");
        return false;
    }
    if (callBundleName == Constants::FRS_BUNDLE_NAME) {
        HILOG_INFO("FRS call");
        return true;
    }

    return false;
}

int32_t FormMgrAdapter::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    FormRecord record;
    std::vector<int64_t> validFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (record.formTempFlag) {
            HILOG_WARN("form %{public}" PRId64 " is temp form", formId);
            continue;
        }
        if (!record.isDynamic) {
            HILOG_WARN("form %{public}" PRId64 " is static form", formId);
            continue;
        }
        if (record.uiSyntax != FormType::ETS) {
            HILOG_WARN("form %{public}" PRId64 " not ETS form", formId);
            continue;
        }
        if (record.recycleStatus != RecycleStatus::NON_RECYCLABLE) {
            HILOG_WARN("form %{public}" PRId64 " is already RECYCLABLE or RECYCLED", formId);
            continue;
        }
        if (std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end()) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }

        record.recycleStatus = RecycleStatus::RECYCLABLE;
        FormDataMgr::GetInstance().UpdateFormRecord(matchedFormId, record);
        validFormIds.emplace_back(matchedFormId);
        HILOG_INFO("formId:%{public}" PRId64 " recyclable", formId);
    }

    if (validFormIds.empty()) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return ERR_OK;
}

int32_t FormMgrAdapter::RecycleForms(const std::vector<int64_t> &formIds, const Want &want, bool isCheckCallingUid)
{
    FormRecord record;
    std::vector<int64_t> validFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (record.formTempFlag) {
            HILOG_WARN("form %{public}" PRId64 " is temp form", formId);
            continue;
        }
        if (!record.isDynamic) {
            HILOG_WARN("form %{public}" PRId64 " is static form", formId);
            continue;
        }
        if (record.uiSyntax != FormType::ETS) {
            HILOG_WARN("form %{public}" PRId64 " not ETS form", formId);
            continue;
        }
        if (record.recycleStatus == RecycleStatus::RECYCLED) {
            HILOG_WARN("form %{public}" PRId64 " is already RECYCLED", formId);
            continue;
        }
        if (isCheckCallingUid && std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end()) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }
        if (!isCheckCallingUid && callingUid < Constants::CALLING_UID_TRANSFORM_DIVISOR) {
            callingUid = *(record.formUserUids.begin());
        }
        record.recycleStatus = RecycleStatus::RECYCLABLE;
        FormDataMgr::GetInstance().UpdateFormRecord(matchedFormId, record);
        validFormIds.emplace_back(matchedFormId);
        HILOG_INFO("formId:%{public}" PRId64 " recyclable", formId);
    }

    if (validFormIds.empty()) {
        HILOG_WARN("empty validFormIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormDataMgr::GetInstance().RecycleForms(validFormIds, callingUid, want);
    return ERR_OK;
}

int32_t FormMgrAdapter::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("call");
    FormRecord record;
    std::vector<int64_t> validFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
        if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (record.recycleStatus == RecycleStatus::RECYCLABLE) {
            HILOG_WARN("form %{public}" PRId64 " is RECYCLABLE, set it to NON_RECYCLABLE", formId);
            FormTaskMgr::GetInstance().CancelDelayTask(std::make_pair((int64_t)TaskType::RECYCLE_FORM, formId));
            record.recycleStatus = RecycleStatus::NON_RECYCLABLE;
            FormDataMgr::GetInstance().UpdateFormRecord(matchedFormId, record);
            continue;
        }
        if (record.recycleStatus != RecycleStatus::RECYCLED) {
            HILOG_WARN("form %{public}" PRId64 " not RECYCLED", formId);
            continue;
        }
        if (std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end() && !IsFormRenderServiceCall(callingUid)) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }

        record.recycleStatus = RecycleStatus::NON_RECYCLABLE;
        FormDataMgr::GetInstance().UpdateFormRecord(matchedFormId, record);
        validFormIds.emplace_back(matchedFormId);
        HILOG_INFO("formId:%{public}" PRId64 " non-recyclable", formId);
    }

    if (validFormIds.empty()) {
        HILOG_WARN("empty validFormIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRenderMgr::GetInstance().RecoverForms(validFormIds, want.GetParams());
    return ERR_OK;
}

ErrCode FormMgrAdapter::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
{
    // find matched formId
    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);

    // check exist and get the formRecord
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form, formId = %{public}" PRId64 " formLocation = %{public}d",
            formId, formLocation);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    if ((int32_t)formRecord.formLocation != formLocation) {
        FormDataMgr::GetInstance().UpdateFormLocation(matchedFormId, formLocation);
        if (!formRecord.formTempFlag) {
            auto ret = HandleFormAddObserver(matchedFormId);
            if (ret != ERR_OK) {
                return ret;
            }
            return FormDbCache::GetInstance().UpdateFormLocation(matchedFormId, formLocation);
        }
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::BatchRefreshForms(const int32_t formRefreshType)
{
    std::vector<FormRecord> visibleFormRecords;
    std::vector<FormRecord> invisibleFormRecords;
    FormDataMgr::GetInstance().GetRecordsByFormType(formRefreshType, visibleFormRecords, invisibleFormRecords);
    HILOG_INFO("getRecords visible size:%{public}zu, invisible size:%{public}zu",
        visibleFormRecords.size(), invisibleFormRecords.size());
    Want reqWant;
    for (auto formRecord : visibleFormRecords) {
        formRecord.isCountTimerRefresh = false;
        formRecord.isTimerRefresh = false;
        FormProviderMgr::GetInstance().ConnectAmsForRefresh(formRecord.formId, formRecord, reqWant, false);
    }
    for (auto formRecord : invisibleFormRecords) {
        formRecord.isCountTimerRefresh = false;
        formRecord.isTimerRefresh = false;
        FormProviderMgr::GetInstance().ConnectAmsForRefresh(formRecord.formId, formRecord, reqWant, false);
    }
    return ERR_OK;
}

#ifdef RES_SCHEDULE_ENABLE
void FormMgrAdapter::SetTimerTaskNeeded(bool isTimerTaskNeeded)
{
    FormTimerMgr::GetInstance().SetTimerTaskNeeded(isTimerTaskNeeded);
}
#endif // RES_SCHEDULE_ENABLE

int32_t FormMgrAdapter::EnableForms(const std::string bundleName, const bool enable)
{
    FormBundleForbidMgr::GetInstance().SetBundleForbiddenStatus(bundleName, !enable);
    std::vector<FormRecord> formInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formInfos)) {
        HILOG_ERROR("GetFormRecord error");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    if (enable) {
        FormRenderMgr::GetInstance().ExecAcquireProviderForbiddenTask(bundleName);
    }
    int32_t userId = FormUtil::GetCurrentAccountId();
    HILOG_INFO("userId:%{public}d, infosSize:%{public}zu, enable:%{public}d", userId, formInfos.size(), enable);
    for (auto iter = formInfos.begin(); iter != formInfos.end();) {
        HILOG_DEBUG("bundleName:%{public}s, enableForm:%{public}d, transparencyEnabled:%{public}d",
            iter->bundleName.c_str(), iter->enableForm, iter->transparencyEnabled);
        if (iter->enableForm == enable || iter->transparencyEnabled) {
            iter = formInfos.erase(iter);
            continue;
        }
        iter->enableForm = enable;
        FormDataMgr::GetInstance().SetFormEnable(iter->formId, enable);
        FormDbCache::GetInstance().UpdateDBRecord(iter->formId, *iter);
        if (enable) {
            if (iter->isRefreshDuringDisableForm) {
                iter->isRefreshDuringDisableForm = false;
                Want want;
                want.SetElementName(iter->bundleName, iter->abilityName);
                want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
                want.SetParam(Constants::RECREATE_FORM_KEY, true);
                want.SetParam(Constants::PARAM_MODULE_NAME_KEY, iter->moduleName);
                want.SetParam(Constants::PARAM_FORM_NAME_KEY, iter->formName);
                want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, iter->specification);
                want.SetParam(Constants::PARAM_FORM_RENDERINGMODE_KEY, static_cast<int32_t>(iter->renderingMode));
                want.SetParam(Constants::PARAM_DYNAMIC_NAME_KEY, iter->isDynamic);
                want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, iter->formTempFlag);
                FormProviderMgr::GetInstance().RefreshForm(iter->formId, want, true);
            } else if (iter->isUpdateDuringDisableForm) {
                iter->isUpdateDuringDisableForm = false;
                FormProviderData data = iter->formProviderInfo.GetFormData();
                WantParams wantParams;
                FormRenderMgr::GetInstance().UpdateRenderingForm(iter->formId, data, wantParams, true);
            }
        }
        ++iter;
    }
    if (!formInfos.empty()) {
        FormDataMgr::GetInstance().EnableForms(std::move(formInfos), enable);
    }
    return ERR_OK;
}

ErrCode FormMgrAdapter::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth)
{
    FormRenderMgr::GetInstance().UpdateFormSize(formId, width, height, borderWidth);
    return ERR_OK;
}

int32_t FormMgrAdapter::OnNotifyRefreshForm(const int64_t &formId)
{
    const int32_t jurgeMs = 100;
    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    int64_t lastTime = 0;
    bool isUpdate = false;
    {
        std::lock_guard<std::mutex> lock(reUpdateFormMapMutex_);
        auto search = reUpdateFormMap_.find(formId);
        if (search != reUpdateFormMap_.end()) {
            lastTime = search->second.first;
            isUpdate = search->second.second;
            reUpdateFormMap_.erase(formId);
        } else {
            return ERR_OK;
        }
    }

    if (currentTime - lastTime < jurgeMs && isUpdate) {
        FormRecord formInfo;
        if (!FormDataMgr::GetInstance().GetFormRecord(formId, formInfo)) {
            HILOG_ERROR("GetFormRecord error");
            return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        }
        HILOG_INFO("RefreshForm");
        int32_t userId = FormUtil::GetCurrentAccountId();
        Want want;
        want.SetElementName(formInfo.bundleName, formInfo.abilityName);
        want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
        want.SetParam(Constants::RECREATE_FORM_KEY, true);
        want.SetParam(Constants::PARAM_MODULE_NAME_KEY, formInfo.moduleName);
        want.SetParam(Constants::PARAM_FORM_NAME_KEY, formInfo.formName);
        want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, formInfo.specification);
        want.SetParam(Constants::PARAM_FORM_RENDERINGMODE_KEY, static_cast<int32_t>(formInfo.renderingMode));
        want.SetParam(Constants::PARAM_DYNAMIC_NAME_KEY, formInfo.isDynamic);
        want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, formInfo.formTempFlag);
        FormProviderMgr::GetInstance().RefreshForm(formId, want, true);
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
