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

#include "form_mgr/form_lifecycle_adapter.h"

#include <regex>
#include <set>

#include "app_log_wrapper.h"
#include "bundle_active_client.h"
#include "bundle_info.h"
#include "configuration.h"
#include "form_constants.h"
#include "form_js_info.h"
#include "form_provider_data.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "want.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/event/form_event_notify_connection.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_report.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "feature/param_update/param_control.h"
#include "form_constants.h"
#include "form_event_report.h"
#include "form_host/form_host_record.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr/form_publish_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider/connection/form_cast_temp_connection.h"
#include "form_provider/form_provider_mgr.h"
#include "form_provider/form_supply_callback.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_render/form_render_mgr.h"
#include "status_mgr_center/form_status.h"
#ifdef THEME_MGR_ENABLE
#include "feature/theme_form/form_theme_form_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
// Constants for FormLifecycleAdapter
}

FormLifecycleAdapter::FormLifecycleAdapter(
    FormDataMgr* formDataMgr,
    FormInfoMgr* formInfoMgr,
    FormProviderMgr* formProviderMgr,
    FormRenderMgr* formRenderMgr,
    FormCommonAdapter* commonAdapter)
    : formDataMgr_(formDataMgr),
      formInfoMgr_(formInfoMgr),
      formProviderMgr_(formProviderMgr),
      formRenderMgr_(formRenderMgr),
      commonAdapter_(commonAdapter),
{
}

// Implementation of CheckFormCountLimit
ErrCode FormLifecycleAdapter::CheckFormCountLimit(const int64_t formId, const Want &want)
{
    HILOG_DEBUG("call");
    bool tempFormFlag = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t currentUserId = FormUtil::GetCallerUserId(callingUid);
    ErrCode checkCode = 0;
    if (tempFormFlag && ((formId == 0) || !FormRenderMgr::GetInstance().IsRerenderForRenderServiceDied(formId))) {
        if (formId > 0) {
            HILOG_ERROR("invalid tempFormId, formId:%{public}" PRId64 "", formId);
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        checkCode = formDataMgr_->CheckTempEnoughForm(currentUserId);
    } else {
        if (formId == 0) {
            checkCode = formDataMgr_->CheckEnoughForm(callingUid, currentUserId);
        }
    }
    if (checkCode != 0) {
        HILOG_ERROR("too much forms in system");
    }
    return checkCode;
}

// Implementation of AllotForm
ErrCode FormLifecycleAdapter::AllotForm(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo, const FormItemInfo &formItemInfo)
{
    HILOG_DEBUG("call");
    Want newWant(want);
    bool directCallInApp = newWant.GetBoolParam(Constants::KEY_DIRECT_CALL_INAPP, false);
    // in application form
    if (formItemInfo.GetProviderBundleName() == formItemInfo.GetHostBundleName() && directCallInApp) {
        HILOG_DEBUG("form in application");
        newWant.SetParam(Constants::PARAM_FORM_HOST_TOKEN, callerToken);
    }

    WantParams wantParams = newWant.GetParams();

    // share form - placeholder for form share logic

    // Specify the form Id
    bool specificFormFlag = false;
    if (want.HasParameter(Constants::PARAM_FORM_MIGRATE_FORM_KEY)) {
        specificFormFlag = want.GetBoolParam(Constants::PARAM_FORM_MIGRATE_FORM_KEY, false);
        HILOG_INFO("migrate_form is %{public}d", specificFormFlag);
        wantParams.Remove(Constants::PARAM_FORM_MIGRATE_FORM_KEY);
    }

    if (!formItemInfo.IsTransparencyEnabled()) {
        wantParams.Remove(Constants::PARAM_FORM_TRANSPARENCY_KEY);
    }

    ErrCode ret = ERR_OK;
    if (formId > 0) {
        if (specificFormFlag) {
            ret = AllotFormBySpecificId(formItemInfo, callerToken, wantParams, formJsInfo);
        } else {
            ret = AllotFormById(formItemInfo, callerToken, wantParams, formJsInfo);
        }
    } else {
        ret = AllotFormByInfo(formItemInfo, callerToken, wantParams, formJsInfo);
    }

    formDataMgr_->UpdateFormHostParams(formJsInfo.formId, want);
    return ret;
}

void FormLifecycleAdapter::CheckIsAddFormByHost(const FormRecord &formRecord, Want &allotFormWant)
{
    bool isAddFormByHost = allotFormWant.GetBoolParam(Constants::IS_ADD_FORM_BY_HOST, false);
    if (isAddFormByHost) {
        return;
    }
    int64_t formId = formRecord.formId;
    HILOG_INFO("formId: %{public}" PRId64 " is not add form by host, update want.", formId);
    FormDataMgr::GetInstance().GetFormHostParams(formId, allotFormWant);
    FormInfo formInfo;
    FormInfoMgr::GetInstance().GetFormsInfoByRecord(formRecord, formInfo);
    if (formInfo.enableBlurBackground) {
        allotFormWant.SetParam(Constants::PARAM_FORM_ENABLE_BLUR_BACKGROUND_KEY, true);
    }
}

ErrCode FormLifecycleAdapter::AddExistFormRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
    const FormRecord &record, const int64_t formId, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_WARN("add exist formRecord, formId:%{public}" PRId64, formId);
    // allot form host record
    int callingUid = IPCSkeleton::GetCallingUid();
    bool isCreated = FormDataMgr::GetInstance().AllotFormHostRecord(info, callerToken, formId, callingUid);
    if (!isCreated) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord, formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    FormRecord newRecord(record);
    std::string cacheData;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    bool hasCacheData = FormCacheMgr::GetInstance().GetData(formId, cacheData, imageDataMap);
    if (hasCacheData) {
        newRecord.formProviderInfo.SetFormDataString(cacheData);
        newRecord.formProviderInfo.SetImageDataMap(imageDataMap);
    }
    FormRenderMgr::GetInstance().RenderForm(newRecord, wantParams, callerToken);
    if (newRecord.needRefresh || newRecord.needAddForm
        || FormCacheMgr::GetInstance().NeedAcquireProviderData(newRecord.formId)
        || wantParams.HasParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY)) {
        HILOG_INFO("acquire ProviderFormInfo async, formId:%{public}" PRId64, formId);
        newRecord.isInited = false;
        FormDataMgr::GetInstance().SetFormCacheInited(formId, false);
        FormDataMgr::GetInstance().SetNeedAddForm(formId, false);
        // Note: AcquireProviderFormInfoAsync moved to FormDataAdapter
        // This needs to be called through FormDataAdapter
    } else if (newRecord.isLocationChange) {
        Want locationWant;
        locationWant.SetParams(wantParams);
        FormProviderMgr::GetInstance().ConnectAmsChangeLocation(formId, newRecord, locationWant);
    }

    // Add new form user uid.
    FormDataMgr::GetInstance().AddFormUserUid(formId, callingUid);
    if (std::find(newRecord.formUserUids.begin(), newRecord.formUserUids.end(), callingUid) ==
        newRecord.formUserUids.end()) {
        newRecord.formUserUids.emplace_back(callingUid);
    }

    FormDataMgr::GetInstance().CreateFormJsInfo(formId, newRecord, formInfo);

    // Note: UpdateTimer moved to FormDataAdapter
    return commonAdapter_->AddFormTimer(newRecord);
}

ErrCode FormLifecycleAdapter::AllotFormById(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    int64_t formId = FormDataMgr::GetInstance().PaddingUdidHash(info.GetFormId());
    HILOG_WARN("call, formId:%{public}" PRId64, formId);
    FormRecord record;
    bool hasRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    record.enableForm = info.IsEnableForm();

    Want allotFormWant;
    allotFormWant.SetParams(wantParams);
    if (hasRecord) {
        commonAdapter_->CheckUpdateFormRecord(formId, info, record);
        if (record.formTempFlag && !FormRenderMgr::GetInstance().IsRerenderForRenderServiceDied(formId)) {
            HILOG_ERROR("addForm can't acquire tempForm when select formId");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        CheckIsAddFormByHost(record, allotFormWant);
    }
    const WantParams wholeWantParams = allotFormWant.GetParams();
    record.formLocation = info.GetFormLocation();

    // ark ts form can only exist with one form host
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (info.GetUiSyntax() == FormType::ETS && !FormDbCache::GetInstance().IsHostOwner(formId, callingUid)) {
        HILOG_ERROR("the specified form id does not exist in caller. formId:%{public}s",
            std::to_string(formId).c_str());
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    int32_t currentUserId = FormUtil::GetCallerUserId(callingUid);
    if (hasRecord && (record.userId == currentUserId)) {
        if (!info.IsMatch(record)) {
            HILOG_ERROR("formId and item info not match:%{public}" PRId64 "", formId);
            return ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID;
        }
        return AddExistFormRecord(info, callerToken, record, formId, wholeWantParams, formInfo);
    }

    // find in db but not in cache
    FormRecord dbRecord;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbRecord);
    if (getDbRet == ERR_OK) {
        if (dbRecord.userId == currentUserId) {
            return AddNewFormRecord(info, formId, callerToken, wholeWantParams, formInfo);
        }
        HILOG_ERROR("the form id does not belong to callerUser. formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    HILOG_INFO("no such formId:%{public}" PRId64, formId);

    // delete form data in provider
    FormRecord delRecord;
    delRecord.bundleName = info.GetProviderBundleName();
    delRecord.abilityName = info.GetAbilityName();
    FormProviderMgr::GetInstance().NotifyProviderFormDelete(formId, delRecord);

    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}

ErrCode FormLifecycleAdapter::AllotFormBySpecificId(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_DEBUG("call");
    // Placeholder implementation
    return AllotFormById(info, callerToken, wantParams, formInfo);
}

ErrCode FormLifecycleAdapter::AllotFormByInfo(const FormItemInfo &info,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo)
{
    HILOG_DEBUG("call");
    // generate formId
    int64_t newFormId = formDataMgr_->GenerateFormId();
    if (newFormId < 0) {
        HILOG_ERROR("generateFormId no invalid formId");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_WARN("Add new form bundleName: %{public}s abilityName: %{public}s formId: %{public}" PRId64,
        formInfo.bundleName.c_str(), formInfo.abilityName.c_str(), newFormId);
    return AddNewFormRecord(info, newFormId, callerToken, wantParams, formInfo);
}

// Implementation of HandleFormRemoveObserver
void FormLifecycleAdapter::HandleFormRemoveObserver(const RunningFormInfo runningFormInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::string hostBundleName;
    auto ret = FormBmsHelper::GetInstance().GetCallerBundleName(hostBundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return;
    }
    formDataMgr_->HandleFormRemoveObserver(hostBundleName, runningFormInfo);
}

// Implementation of HandleDeleteTempForm
ErrCode FormLifecycleAdapter::HandleDeleteTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    int uid = IPCSkeleton::GetCallingUid();
    FormRecord record;
    bool isFormRecExist = formDataMgr_->GetFormRecord(formId, record);
    bool isSelfTempFormId = false;
    if (isFormRecExist && record.formTempFlag) {
        isSelfTempFormId = (FormUtil::GetCallerUserId(uid) == record.providerUserId) &&
            ((std::find(record.formUserUids.begin(), record.formUserUids.end(), uid) !=
            record.formUserUids.end()) ? true : false);
    }
    if (!isSelfTempFormId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }
    formRenderMgr_->StopRenderingForm(formId, record, "", callerToken);
    formDataMgr_->DeleteFormUserUid(formId, uid);
    if (!formDataMgr_->HasFormUserUids(formId)) {
        int result = formProviderMgr_->NotifyProviderFormDelete(formId, record);
        if (result != ERR_OK) {
            HILOG_ERROR("fail");
            formDataMgr_->AddFormUserUid(formId, uid);
            return result;
        }
        if (!formDataMgr_->DeleteTempForm(formId)) {
            HILOG_ERROR("formId not exist");
            return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
        }
        formDataMgr_->DeleteFormRecord(formId);
        if (!FormCacheMgr::GetInstance().DeleteData(formId)) {
            HILOG_ERROR("fail remove cache data");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    if (!formDataMgr_->DeleteHostRecord(callerToken, formId)) {
        HILOG_ERROR("fail remove host record");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    HILOG_DEBUG("record.formUserUids size:%{public}zu", record.formUserUids.size());
    return ERR_OK;
}

// Implementation of HandleDeleteForm
ErrCode FormLifecycleAdapter::HandleDeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    FormRecord dbRecord;
    if (FormDbCache::GetInstance().GetDBRecord(formId, dbRecord) != ERR_OK) {
        HILOG_ERROR("not exist such db form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    FormRecord record;
    formDataMgr_->GetFormRecord(formId, record);
    formRenderMgr_->StopRenderingForm(formId, record, "", callerToken);

#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    DeviceUsageStats::BundleActiveEvent event(record.bundleName, record.moduleName, record.formName,
        record.specification, record.formId, DeviceUsageStats::BundleActiveEvent::FORM_IS_REMOVED);
#endif
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    bool isSelfDbFormId = (userId == dbRecord.providerUserId) && ((std::find(dbRecord.formUserUids.begin(),
        dbRecord.formUserUids.end(), callingUid) != dbRecord.formUserUids.end()) ? true : false);
    if (!isSelfDbFormId) {
        HILOG_ERROR("not self form:%{public}" PRId64 ", callingUid:%{public}d", formId, callingUid);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    ErrCode result = HandleDeleteFormCache(dbRecord, callingUid, formId);
    if (result != ERR_OK) {
        HILOG_ERROR("handle delete form cache failed, formId:%{public}" PRId64, formId);
        return result;
    }

    if (!formDataMgr_->DeleteHostRecord(callerToken, formId)) {
        HILOG_ERROR("fail remove host record, formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

#ifdef DEVICE_USAGE_STATISTICS_ENABLE
    DeviceUsageStats::BundleActiveClient::GetInstance().ReportEvent(event, userId);
#endif
    return ERR_OK;
}

ErrCode FormLifecycleAdapter::HandleDeleteFormCache(FormRecord &dbRecord, const int uid, const int64_t formId)
{
    auto iter = std::find(dbRecord.formUserUids.begin(), dbRecord.formUserUids.end(), uid);
    if (iter != dbRecord.formUserUids.end()) {
        dbRecord.formUserUids.erase(iter);
    }

    ErrCode result = ERR_OK;
    int32_t deleteFormError = ERR_OK;
    if (dbRecord.formUserUids.empty()) {
        result = formProviderMgr_->NotifyProviderFormDelete(formId, dbRecord);
        if (result != ERR_OK) {
            HILOG_ERROR("notify providerForm delete failed");
            deleteFormError = deleteFormError != ERR_OK ? deleteFormError : result;
        }
        if (!formDataMgr_->DeleteFormRecord(formId)) {
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
    formDataMgr_->DeleteFormUserUid(formId, uid);
    return result;
}

// Implementation of HandleReleaseForm
ErrCode FormLifecycleAdapter::HandleReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
#ifndef WATCH_API_DISABLE
    HILOG_WARN("formId:%{public}" PRId64, formId);
    if (!formDataMgr_->ExistFormRecord(formId)) {
        HILOG_ERROR("not exist such db or temp form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord hostRecord;
    bool hasRecord = formDataMgr_->GetMatchedHostClient(callerToken, hostRecord);
    bool isSelfId = hasRecord && hostRecord.Contains(formId);
    if (!isSelfId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    formDataMgr_->DeleteFormUserUid(formId, IPCSkeleton::GetCallingUid());
    if (!formDataMgr_->HasFormUserUids(formId)) {
        formDataMgr_->DeleteFormRecord(formId);
        if (!FormTimerMgr::GetInstance().RemoveFormTimer(formId)) {
            HILOG_ERROR("remove timer error");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    return ERR_OK;
#else
    return ERR_OK;
#endif
}

#ifdef THEME_MGR_ENABLE
int FormLifecycleAdapter::DeleteThemeForm(const int64_t formId)
{
    HILOG_INFO("call");
    std::vector<int64_t> removeList;
    removeList.emplace_back(formId);
    int ret = ThemeFormClient::GetInstance().DeleteForms(removeList);
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

int FormLifecycleAdapter::DeleteCommonForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const int32_t userId)
{
    int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
    FormSupplyCallback::GetInstance()->RemoveConnection(matchedFormId, callerToken);
    FormDataProxyMgr::GetInstance().UnsubscribeFormData(matchedFormId);
    RunningFormInfo runningFormInfo;
    formDataMgr_->GetRunningFormInfosByFormId(matchedFormId, runningFormInfo, userId);

    if (formDataMgr_->ExistTempForm(matchedFormId)) {
        int ret = HandleDeleteTempForm(matchedFormId, callerToken);
        if (ret != ERR_OK) {
            FormEventReport::SendFormFailedEvent(FormEventName::DELETE_FORM_FAILED, formId, runningFormInfo.bundleName,
                runningFormInfo.formName, static_cast<int32_t>(DeleteFormErrorType::DELETE_TEMP_FORM_FAILED), ret);
        }
        return ret;
    }

    int ret = HandleDeleteForm(matchedFormId, callerToken);
    if (ret != ERR_OK) {
        HILOG_ERROR("delete failed, formId:%{public}" PRId64, formId);
        FormEventReport::SendFormFailedEvent(FormEventName::DELETE_FORM_FAILED, formId, runningFormInfo.bundleName,
            runningFormInfo.formName, static_cast<int32_t>(DeleteFormErrorType::DELETE_NORMAL_FORM_FAILED), ret);
        return ret;
    }

    HILOG_DEBUG("Checks if there is a listener listening for release form");
    HandleFormRemoveObserver(runningFormInfo);
    return ERR_OK;
}

int FormLifecycleAdapter::AddForm(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    if (formId < 0 || callerToken == nullptr) {
        HILOG_ERROR("param error, formId: %{public}" PRId64 " code: %{public}d",
            formId, ERR_APPEXECFWK_FORM_INVALID_PARAM);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    AddFormResultErrorCodes states = AddFormResultErrorCodes::SUCCESS;
    ErrCode ret = publishAdapter_->CheckAddFormTaskTimeoutOrFailed(formId, states);
    if (ret != ERR_OK) {
        HILOG_ERROR("AddForm Task Timeout or Failed. formId: %{public}" PRId64 " code: %{public}d", formId, ret);
        return ret;
    }

    ret = CheckFormCountLimit(formId, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("CheckFormCountLimit failed. formId: %{public}" PRId64 " code: %{public}d", formId, ret);
        return ret;
    }

    if (formId > 0) {
        FormReport::GetInstance().InsertFormId(formId);
        HILOG_DEBUG("HiSysevent Insert Formid");
    }

    FormItemInfo formItemInfo;
    formItemInfo.SetFormId(formId);
    int32_t errCode = commonAdapter_->GetFormConfigInfo(want, formItemInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get %{public}s form config info failed. formId: %{public}" PRId64 " code: %{public}d",
            formJsInfo.bundleName.c_str(), formId, errCode);
        return errCode;
    }

    if (!FormTrustMgr::GetInstance().IsTrust(formItemInfo.GetProviderBundleName())) {
        HILOG_ERROR("AddForm fail,%{public}s is unTrust. formId: %{public}" PRId64 " code: %{public}d",
            formItemInfo.GetProviderBundleName().c_str(), formId, ERR_APPEXECFWK_FORM_NOT_TRUST);
        return ERR_APPEXECFWK_FORM_NOT_TRUST;
    }

    int32_t dimensionId = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
    FormMajorInfo formMajorInfo;
    formMajorInfo.bundleName = formItemInfo.GetProviderBundleName();
    formMajorInfo.moduleName = formItemInfo.GetModuleName();
    formMajorInfo.abilityName = formItemInfo.GetAbilityName();
    formMajorInfo.formName = formItemInfo.GetFormName();
    formMajorInfo.dimension = dimensionId;

    if (formId == 0 && commonAdapter_->CheckFormDueControl(formMajorInfo, false)) {
        HILOG_ERROR("Add new form fail,%{public}s is due removed. formId: %{public}" PRId64 " code: %{public}d",
            formItemInfo.GetProviderBundleName().c_str(), formId, ERR_APPEXECFWK_FORM_DUE_REMOVE);
        return ERR_APPEXECFWK_FORM_DUE_REMOVE;
    }

    if (formId > 0 && formDataMgr_->IsRequestPublishForm(formId)) {
        ret = AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo);
        if (ret != ERR_OK) {
            HILOG_ERROR("add request publish form failed. formId: %{public}" PRId64 " code: %{public}d", formId, ret);
            return ret;
        }
        bool tempFormFlag = want.GetBoolParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
        if (!tempFormFlag && (ret == ERR_OK)) {
            HILOG_DEBUG("Checks if there is a listener listening for adding form");
            commonAdapter_->HandleFormAddObserver(formJsInfo.formId);
        }
    }

    if (states == AddFormResultErrorCodes::UNKNOWN) {
        publishAdapter_->CancelAddFormRequestTimeOutTask(formId, ret);
    }

    ret = AllotForm(formId, want, callerToken, formJsInfo, formItemInfo);
    publishAdapter_->RemoveFormIdMapElement(formId);
    if (ret != ERR_OK) {
        HILOG_ERROR("allot form failed. formId: %{public}" PRId64 " code: %{public}d", formId, ret);
    }
    return ret;
}

int FormLifecycleAdapter::DeleteForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_WARN("formId:%{public}" PRId64, formId);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("deleteForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t userId = FormUtil::GetCallerUserId(IPCSkeleton::GetCallingUid());
    FormRenderMgr::GetInstance().DeleteAcquireForbiddenTaskByFormId(formId);
    RefreshCacheMgr::GetInstance().DelRenderTask(formId);
    formDataMgr_->DeleteFormVisible(formId);

#ifdef THEME_MGR_ENABLE
    FormDBInfo dbInfo;
    ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(formId, dbInfo);
    HILOG_INFO("getDbRet:%{public}d, isThemeForm:%{public}d", getDbRet, dbInfo.isThemeForm);
    if (getDbRet == ERR_OK && dbInfo.isThemeForm) {
        int32_t ret = DeleteThemeForm(formId);
        if (ret != ERR_OK) {
            FormEventReport::SendFormFailedEvent(FormEventName::DELETE_FORM_FAILED, formId, dbInfo.bundleName,
                dbInfo.formName, static_cast<int32_t>(DeleteFormErrorType::DELETE_THEME_FORM_FAILED), ret);
        }
        return ret;
    }
#endif

    return DeleteCommonForm(formId, callerToken, userId);
}

int FormLifecycleAdapter::ReleaseForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const bool delCache)
{
#ifndef WATCH_API_DISABLE
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_WARN("formId:%{public}" PRId64, formId);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("releaseForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
    FormSupplyCallback::GetInstance()->RemoveConnection(matchedFormId, callerToken);

    if (formDataMgr_->ExistTempForm(matchedFormId)) {
        return HandleDeleteTempForm(matchedFormId, callerToken);
    }

    FormRecord record;
    formDataMgr_->GetFormRecord(formId, record);
    formRenderMgr_->StopRenderingForm(formId, record, "", callerToken);

    FormRecord dbRecord;
    if (FormDbCache::GetInstance().GetDBRecord(matchedFormId, dbRecord) != ERR_OK) {
        HILOG_ERROR("not exist such db form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t callerUserId = FormUtil::GetCallerUserId(callingUid);
    bool isSelfDbFormId = (callerUserId == dbRecord.providerUserId) &&
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

    if (!formDataMgr_->DeleteHostRecord(callerToken, matchedFormId)) {
        HILOG_ERROR("fail remove host record");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!FormTimerMgr::GetInstance().RemoveFormTimer(matchedFormId)) {
        HILOG_ERROR("remove timer error");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
#else
    return ERR_OK;
#endif
}

int FormLifecycleAdapter::CastTempForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken)
{
#ifndef WATCH_API_DISABLE
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("invalid formId or callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
    if (!formDataMgr_->ExistFormRecord(matchedFormId) ||
        !formDataMgr_->ExistTempForm(matchedFormId)) {
        HILOG_ERROR("not exist such temp form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    FormHostRecord record;
    bool hasRecord = formDataMgr_->GetMatchedHostClient(callerToken, record);
    bool isSelfId = hasRecord && record.Contains(matchedFormId);
    if (!isSelfId) {
        HILOG_ERROR("not self form:%{public}" PRId64 "", matchedFormId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    int checkCode = formDataMgr_->CheckEnoughForm(callingUid, userId, true);
    if (checkCode != 0) {
        HILOG_ERROR("%{public}" PRId64 " failed,because if too mush forms", matchedFormId);
        return checkCode;
    }

    FormRecord formRecord;
    if (!formDataMgr_->GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    int bindSupplierCheckCode = HandleCastTempForm(matchedFormId, formRecord);
    if (bindSupplierCheckCode != 0) {
        HILOG_ERROR("cast temp form bindSupplier failed");
        return bindSupplierCheckCode;
    }

    if (!formDataMgr_->DeleteTempForm(matchedFormId)) {
        HILOG_ERROR("delete temp form error, formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (!formDataMgr_->ModifyFormTempFlag(matchedFormId, false)) {
        HILOG_ERROR("modify form temp flag error, formId:%{public}" PRId64 ".",
            matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (!formDataMgr_->AddFormUserUid(matchedFormId, callingUid)) {
        HILOG_ERROR("add form user uid error, formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (!formDataMgr_->GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    ErrCode errorCode = FormDbCache::GetInstance().UpdateDBRecord(matchedFormId, formRecord);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("update db record error, formId:%{public}" PRId64 ".", matchedFormId);
        return errorCode;
    }

    return commonAdapter_->AddFormTimer(formRecord);
#else
    return ERR_OK;
#endif
}

int FormLifecycleAdapter::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
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

        int64_t formId = formDataMgr_->GenerateFormId();
        HILOG_INFO("generate formId:%{public}" PRId64, formId);
        if (formId < 0) {
            HILOG_ERROR("generate invalid formId");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        FormNotifyInfo info = {formId, want};
        ret = ThemeFormClient::GetInstance().AddForm(info);
        if (ret != ERR_OK) {
            HILOG_ERROR("ThemeManager AddForm failed");
            return ret;
        }

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

int FormLifecycleAdapter::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("deleteForm invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRecord record;
    formDataMgr_->GetFormRecord(formId, record);
    formRenderMgr_->StopRenderingForm(formId, record, compId);
    return ERR_OK;
}

int FormLifecycleAdapter::DeleteInvalidForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::set<int64_t> matchedFormIds {};
    for (int64_t formId : formIds) {
        int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
        matchedFormIds.emplace(matchedFormId);
        HILOG_INFO("valid formId, formId:%{public}" PRId64, formId);
    }
    std::map<int64_t, bool> removedFormsMap {};
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    HILOG_WARN("userId:%{public}d, callingUid:%{public}d", userId, callingUid);
    FormDbCache::GetInstance().DeleteInvalidDBForms(userId, callingUid, matchedFormIds, removedFormsMap);
    formDataMgr_->DeleteInvalidTempForms(userId, callingUid, matchedFormIds, removedFormsMap);

    if (!removedFormsMap.empty()) {
        formDataMgr_->ClearHostDataByInvalidForms(callingUid, removedFormsMap);
        for (const auto &removedForm : removedFormsMap) {
            if (removedForm.second) {
                FormTimerMgr::GetInstance().RemoveFormTimer(removedForm.first);
                formRenderMgr_->DeleteAcquireForbiddenTaskByFormId(removedForm.first);
                RefreshCacheMgr::GetInstance().DelRenderTask(removedForm.first);
                formDataMgr_->DeleteFormVisible(removedForm.first);
            }
        }
    }

    std::string bundleName;
    if (FormBmsHelper::GetInstance().GetCallerBundleName(bundleName) == ERR_OK) {
        formDataMgr_->DeleteInvalidPublishForms(userId, bundleName, matchedFormIds);
    }

    numFormsDeleted = static_cast<int32_t>(removedFormsMap.size());
    HILOG_INFO("done,%{public}d forms, deleted", numFormsDeleted);
    return ERR_OK;
}

#ifdef THEME_MGR_ENABLE
int FormLifecycleAdapter::AddThemeDBRecord(const Want &want, int64_t formId)
{
    HILOG_DEBUG("call");
    FormRecord formRecord = AllotThemeRecord(want, formId);
    int ret = FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateDBRecord failed");
    }
    return ret;
}

FormRecord FormLifecycleAdapter::AllotThemeRecord(const Want &want, int64_t formId)
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
    int32_t currentUserId = FormUtil::GetCallerUserId(callingUid);
    return formDataMgr_->AllotFormRecord(formInfo, callingUid, currentUserId);
}
#endif

// Implementation of EnableForms
ErrCode FormLifecycleAdapter::EnableForms(const std::string &bundleName, const int32_t userId, const bool enable)
{
    FormBundleForbidMgr::GetInstance().SetBundleForbiddenStatus(bundleName, !enable);
    std::vector<FormRecord> formInfos;
    if (!formDataMgr_->GetFormRecord(bundleName, formInfos)) {
        HILOG_ERROR("GetFormRecord error");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    HILOG_INFO("userId:%{public}d, bundleName:%{public}s, infosSize:%{public}zu, enable:%{public}d",
        userId, bundleName.c_str(), formInfos.size(), enable);
    for (auto iter = formInfos.begin(); iter != formInfos.end();) {
        HILOG_DEBUG("enableForm:%{public}d, transparencyEnabled:%{public}d",
            iter->enableForm, iter->transparencyEnabled);
        if (enable) {
            formRenderMgr_->ExecAcquireProviderForbiddenTaskByFormId(iter->formId);
        }
        if (iter->enableForm == enable || iter->providerUserId != userId) {
            iter = formInfos.erase(iter);
            continue;
        }
        iter->enableForm = enable;
        formDataMgr_->SetFormEnable(iter->formId, enable);
        FormDbCache::GetInstance().UpdateDBRecord(iter->formId, *iter);
        if (enable) {
            RefreshCacheMgr::GetInstance().ConsumeHealthyControlFlag(iter, userId);
        }
        ++iter;
    }
    if (!formInfos.empty()) {
        formDataMgr_->EnableForms(std::move(formInfos), enable);
    }
    return ERR_OK;
}

// Implementation of ProtectLockForms
ErrCode FormLifecycleAdapter::ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect)
{
    HILOG_INFO("ProtectLockForms entry");
    if (FormBundleLockMgr::GetInstance().IsBundleProtect(bundleName, userId) == protect) {
        HILOG_INFO("No need to change protect status, bundleName = %{public}s, protect = %{public}d",
            bundleName.c_str(), protect);
        return ERR_OK;
    }
    FormBundleLockMgr::GetInstance().SetBundleProtectStatus(bundleName, protect);
    std::vector<FormRecord> formInfos;
    if (!formDataMgr_->GetFormRecord(bundleName, formInfos, userId)) {
        HILOG_ERROR("GetFormRecord error");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    if (!protect && !FormBundleForbidMgr::GetInstance().IsBundleForbidden(bundleName)) {
        formRenderMgr_->ExecAcquireProviderForbiddenTask(bundleName);
    }

    HILOG_INFO("userId:%{public}d, infosSize:%{public}zu, protect:%{public}d", userId, formInfos.size(), protect);
    for (auto iter = formInfos.begin(); iter != formInfos.end();) {
        HILOG_DEBUG("bundleName:%{public}s, lockForm:%{public}d, transparencyEnabled:%{public}d",
            iter->bundleName.c_str(), iter->lockForm, iter->transparencyEnabled);
        if (FormExemptLockMgr::GetInstance().IsExemptLock(iter->formId)) {
            iter = formInfos.erase(iter);
            continue;
        }
        iter->protectForm = protect;
        formDataMgr_->SetFormProtect(iter->formId, protect);
        FormDbCache::GetInstance().UpdateDBRecord(iter->formId, *iter);
        ++iter;
    }
    if (!formInfos.empty()) {
        formDataMgr_->LockForms(std::move(formInfos), protect);
    }
    return ERR_OK;
}

// Implementation of RecoverForms
int32_t FormLifecycleAdapter::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_DEBUG("call");
    FormRecord record;
    std::vector<int64_t> validFormIds;
    std::vector<int64_t> matchedFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    bool needHandleCachedClick =
        want.GetBoolParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, false);
    HILOG_INFO("recover by click: %{public}d", needHandleCachedClick);
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
        formDataMgr_->SetExpectRecycledStatus(matchedFormId, false);
        matchedFormIds.emplace_back(matchedFormId);
        if (!formDataMgr_->GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (!record.isDynamic) {
            HILOG_WARN("form %{public}" PRId64 " is static form", formId);
            continue;
        }
        // Recovery is performed only when the form has been recycled or is recycling, or when there is a
        // recycling task in the queue, or click in recycled form.
        if (!(FormStatus::GetInstance().IsFormProcessRecycle(formId) || record.isExistRecycleTask) &&
            !needHandleCachedClick) {
            HILOG_WARN("form %{public}" PRId64 " not RECYCLED", formId);
            continue;
        }
        if (std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end() && !IsFormRenderServiceCall(callingUid)) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }

        record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
        formDataMgr_->UpdateFormRecord(matchedFormId, record);
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

bool FormLifecycleAdapter::IsFormRenderServiceCall(int callingUid)
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

// Implementation of SwitchLockForms
ErrCode FormLifecycleAdapter::SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock)
{
    HILOG_INFO("SwitchLockForms entry");
    if (FormBundleLockMgr::GetInstance().IsBundleLock(bundleName, userId) == lock) {
        HILOG_INFO("No need to change lock status, bundleName = %{public}s, lock = %{public}d",
            bundleName.c_str(), lock);
        return ERR_OK;
    }
    FormBundleLockMgr::GetInstance().SetBundleLockStatus(bundleName, lock);
    std::vector<FormRecord> formInfos;
    if (!formDataMgr_->GetFormRecord(bundleName, formInfos, userId)) {
        HILOG_ERROR("GetFormRecord error");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    HILOG_INFO("userId:%{public}d, infosSize:%{public}zu, lock:%{public}d", userId, formInfos.size(), lock);
    for (auto iter = formInfos.begin(); iter != formInfos.end();) {
        HILOG_INFO("bundleName:%{public}s, lockForm:%{public}d, formId:%{public}" PRId64,
            iter->bundleName.c_str(), iter->lockForm, iter->formId);
        bool isSystemApp = iter->isSystemApp;
        FormInfo formInfo;
        formInfoMgr_->GetFormsInfoByRecord(*iter, formInfo);
        bool isMultiAppForm = formInfoMgr_->IsMultiAppForm(formInfo);
        if (iter->lockForm == lock || (isSystemApp && isMultiAppForm)) {
            iter = formInfos.erase(iter);
            continue;
        }
        iter->lockForm = lock;
        formDataMgr_->SetFormLock(iter->formId, lock);
        FormDbCache::GetInstance().UpdateDBRecord(iter->formId, *iter);
        if (!lock) {
            FormExemptLockMgr::GetInstance().SetExemptLockStatus(iter->formId, false);
        }
        ++iter;
    }

    ErrCode res = ProtectLockForms(bundleName, userId, lock);
    if (res != ERR_OK) {
        HILOG_ERROR("ProtectLockForms faild when executing the switchLockForms");
        return res;
    }
    return ERR_OK;
}

// Implementation of BatchNotifyFormsConfigurationUpdate
ErrCode FormLifecycleAdapter::BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration)
{
    std::vector<FormRecord> visibleFormRecords;
    std::vector<FormRecord> invisibleFormRecords;
    std::set<std::string> notified;
    formDataMgr_->GetRecordsByFormType(Constants::REFRESH_SYSTEMAPP_FORM,
        visibleFormRecords, invisibleFormRecords);
    HILOG_INFO("getRecords visible size:%{public}zu, invisible size:%{public}zu",
        visibleFormRecords.size(), invisibleFormRecords.size());
    Want reqWant;
    for (auto formRecord : visibleFormRecords) {
        if (notified.find(formRecord.bundleName + formRecord.abilityName) != notified.end()) {
            continue;
        }
        notified.insert(formRecord.bundleName + formRecord.abilityName);
        formProviderMgr_->ConnectForConfigUpdate(configuration, formRecord, reqWant);
    }
    for (auto formRecord : invisibleFormRecords) {
        if (notified.find(formRecord.bundleName + formRecord.abilityName) != notified.end()) {
            continue;
        }
        notified.insert(formRecord.bundleName + formRecord.abilityName);
        formProviderMgr_->ConnectForConfigUpdate(configuration, formRecord, reqWant);
    }
return ERR_OK;
}

// Implementation of AddRequestPublishForm
ErrCode FormLifecycleAdapter::AddRequestPublishForm(const FormItemInfo &formItemInfo, const Want &want,
    const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo)
{
    HILOG_INFO("call");
    Want formProviderWant;
    std::unique_ptr<FormProviderData> formProviderData = nullptr;
    auto formId = formItemInfo.GetFormId();
    ErrCode errCode = formDataMgr_->GetRequestPublishFormInfo(formId, formProviderWant, formProviderData);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get requestPublishForm");
        return errCode;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!formDataMgr_->AllotFormHostRecord(formItemInfo, callerToken, formId, callingUid)) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // get current userId
    int32_t currentUserId = FormUtil::GetCallerUserId(callingUid);
    // allot form record
    FormRecord formRecord = formDataMgr_->AllotFormRecord(formItemInfo, callingUid, currentUserId);
    if (formProviderData != nullptr) {
        formRecord.formProviderInfo.SetFormData(*formProviderData);
    }
    FormRenderMgr::GetInstance().RenderForm(formRecord, want.GetParams()); // render for arkTs form

    // create form info for js
    formDataMgr_->CreateFormJsInfo(formId, formRecord, formJsInfo);
    formDataMgr_->SetNeedAddForm(formId, true);
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
        FormDataProxyMgr::GetInstance().SubscribeFormData(formId, formDataProxies, want, currentUserId);
    }
    // start update timer
    return commonAdapter_->AddFormTimer(formRecord);
}

// Implementation of AddNewFormRecord
ErrCode FormLifecycleAdapter::AddNewFormRecord(const FormItemInfo &info, const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formJsInfo)
{
    HILOG_WARN("call formId: %{public}" PRId64, formId);
    FormItemInfo newInfo(info);
    newInfo.SetFormId(formId);
    // allot form host record
    int callingUid = IPCSkeleton::GetCallingUid();
    if (!formDataMgr_->AllotFormHostRecord(newInfo, callerToken, formId, callingUid)) {
        HILOG_ERROR("AllotFormHostRecord failed when no matched formRecord, formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // get current userId
    int32_t currentUserId = FormUtil::GetCallerUserId(callingUid);
    // allot form record
    FormRecord formRecord = formDataMgr_->AllotFormRecord(newInfo, callingUid, currentUserId);

    FormRenderMgr::GetInstance().RenderForm(formRecord, wantParams, callerToken);

    // Note: AcquireProviderFormInfoAsync moved to FormDataAdapter
    // This needs to be called through FormDataAdapter

    // create form info for js
    formDataMgr_->CreateFormJsInfo(formId, formRecord, formJsInfo);

    // storage info
    if (!newInfo.IsTemporaryForm()) {
        ErrCode errorCode = FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord);
        if (errorCode != ERR_OK) {
            HILOG_ERROR("UpdateDBRecord failed, formId:%{public}" PRId64, formId);
            return errorCode;
        }
    }

    if (!formRecord.isSystemApp && formRecord.transparencyEnabled) {
        FormTimerMgr::GetInstance().StartFormCheckTimer();
    }
    // start update timer
    if (info.GetProviderBundleName() != info.GetHostBundleName()) {
        return commonAdapter_->AddFormTimer(formRecord);
    }
    return ERR_OK;
}

// Implementation of HandleCastTempForm with complete implementation
ErrCode FormLifecycleAdapter::HandleCastTempForm(const int64_t formId, const FormRecord &formRecord)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("cast temp form to normal form, notify supplier, package:%{public}s, class:%{public}s",
        formRecord.bundleName.c_str(), formRecord.abilityName.c_str());
    sptr<IAbilityConnection> castTempConnection = new FormCastTempConnection(formId,
        formRecord.bundleName, formRecord.abilityName, commonAdapter_->GetCallingUserId());

    Want want;
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    want.SetElementName(formRecord.bundleName, formRecord.abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, castTempConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED,
            formId,
            formRecord.bundleName,
            formRecord.formName,
            static_cast<int32_t>(AddFormFailedErrorType::CONNECT_FORM_PROVIDER_FAILED));
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
#else
    return ERR_OK;
#endif
}

int FormLifecycleAdapter::ReleaseRenderer(const int64_t formId, const std::string &compId)
{
    HILOG_INFO("FormLifecycleAdapter::ReleaseRenderer called, formId:%{public}" PRId64, formId);

    if (formId <= 0 || compId.empty()) {
        HILOG_ERROR("Release invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // Get form record
    FormRecord formRecord;
    if (!formDataMgr_->GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("no matched form record");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    formRenderMgr_->ReleaseRenderer(formId, formRecord, compId);
    return ERR_OK;
}

#ifdef RES_SCHEDULE_ENABLE
void FormLifecycleAdapter::SetTimerTaskNeeded(bool isTimerTaskNeeded)
{
    HILOG_INFO("FormLifecycleAdapter::SetTimerTaskNeeded called, isTimerTaskNeeded:%{public}d", isTimerTaskNeeded);
    RefreshControlMgr::GetInstance().SetSystemOverloadFlag(!isTimerTaskNeeded);
}
#endif // RES_SCHEDULE_ENABLE

} // namespace AppExecFwk
} // namespace OHOS
