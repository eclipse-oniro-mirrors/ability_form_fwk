/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_provider/form_provider_mgr.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "form_provider/connection/form_batch_delete_connection.h"
#include "data_center/form_cache_mgr.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "form_provider/connection/form_delete_connection.h"
#include "form_mgr_errors.h"
#include "form_provider/connection/form_msg_event_connection.h"
#include "data_center/form_record/form_record.h"
#include "form_provider/connection/form_refresh_connection.h"
#include "form_provider/connection/form_location_connection.h"
#include "form_provider/connection/form_configuration_update_connection.h"
#include "form_provider/connection/form_update_size_connection.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_report.h"
#include "data_center/form_record/form_record_report.h"
#include "form_mgr/form_mgr_adapter.h"
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif
#include "form_mgr/form_mgr_queue.h"
#include "form_mgr/form_mgr_queue.h"
#include "common/util/form_task_common.h"
#include "form_event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *HICAR_FORM = "phone_hicar";
}
FormProviderMgr::FormProviderMgr() {}
FormProviderMgr::~FormProviderMgr() {}
/**
 * @brief handle for acquire back from ams.
 * @param formId The id of the form.
 * @param formProviderInfo provider form info.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::AcquireForm(const int64_t formId, const FormProviderInfo &formProviderInfo)
{
    HILOG_DEBUG("formId:%{public}" PRId64 "", formId);

    if (formId <= 0) {
        HILOG_ERROR("formId not greater than 0");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("not exist such form, formId:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    std::vector<FormHostRecord> clientHosts;
    FormDataMgr::GetInstance().GetFormHostRecord(formId, clientHosts);
    if (clientHosts.empty()) {
        HILOG_ERROR("empty clientHosst");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (formRecord.isInited) {
        if (IsFormCached(formRecord)) {
            formRecord.formProviderInfo = formProviderInfo;
            for (auto &iter : clientHosts) {
                iter.OnAcquire(formId, formRecord);
            }
        } else {
            Want want;
            RefreshForm(formId, want, true);
        }
        return ERR_OK;
    }
    formRecord.isInited = true;
    formRecord.needRefresh = false;
    FormDataMgr::GetInstance().SetFormCacheInited(formId, true);

    formRecord.formProviderInfo = formProviderInfo;
    for (auto &iter : clientHosts) {
        iter.OnAcquire(formId, formRecord);
    }

    if (formProviderInfo.NeedCache()) {
        HILOG_WARN("acquire js card,cache the card");
        FormCacheMgr::GetInstance().AddData(formId, formProviderInfo.GetFormData());
    }
    return ERR_OK;
}

void FormProviderMgr::MergeWant(const Want &newWant, Want &oldWant)
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

void FormProviderMgr::UpdateWant(const int64_t formId, const Want &want, FormRecord &record)
{
    if (record.wantCacheMap.size() != 0) {
        MergeWant(want, record.wantCacheMap[formId]);
        return;
    }
    record.wantCacheMap[formId] = want;
}

void FormProviderMgr::DataProxyUpdate(const int64_t formId, const FormRecord &record, bool isFormProviderUpdate)
{
    if (isFormProviderUpdate && record.isDataProxy) {
        FormProviderData formProviderData;
        formProviderData.EnableDbCache(true);
        FormMgrAdapter::GetInstance().UpdateForm(formId, record.uid, formProviderData);
        HILOG_INFO("Upgrade APP data agent card update, formId:%{public}" PRId64, formId);
    }
}

/**
 * @brief Refresh form.
 *
 * @param formId The form id.
 * @param want The want of the form to request.
 * @param isVisibleToFresh The form is visible to fresh.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::RefreshForm(const int64_t formId, const Want &want, bool isVisibleToFresh)
{
    FormRecord record;
    ErrCode result = RefreshCheck(record, formId, want);
    if (result != ERR_OK) {
        return result;
    }
    HILOG_BRIEF("FormProviderMgr::RefreshForm, formId:%{public}" PRId64 "., record.enableForm = %{public}d",
        formId, record.enableForm);
    if (!record.enableForm) {
        FormDataMgr::GetInstance().SetRefreshDuringDisableForm(formId, true);
        FormRecordReport::GetInstance().IncreaseUpdateTimes(formId,
            HiSysEventPointType::TYPE_DISABLE_FORM_INTERCEPT);
        return ERR_APPEXECFWK_FORM_DISABLE_REFRESH;
    }
    bool isCountTimerRefresh = want.GetBoolParam(Constants::KEY_IS_TIMER, false);
    Want newWant(want);
    newWant.RemoveParam(Constants::KEY_IS_TIMER);

    bool isTimerRefresh = want.GetBoolParam(Constants::KEY_TIMER_REFRESH, false);
    bool isConnectRefresh = want.GetBoolParam(Constants::KEY_CONNECT_REFRESH, false);
    newWant.RemoveParam(Constants::KEY_TIMER_REFRESH);
    newWant.RemoveParam(Constants::KEY_CONNECT_REFRESH);

    int refreshType = newWant.GetIntParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_DEFAULT);

    if (isTimerRefresh || isConnectRefresh) {
        FormDataMgr::GetInstance().SetTimerRefresh(formId, true);
        bool isFormVisible = record.formVisibleNotifyState == Constants::FORM_VISIBLE;
        if (!isFormVisible) {
            HILOG_INFO("form is invisible, formId:%{public}" PRId64, formId);
            FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
            FormDataMgr::GetInstance().SetRefreshType(formId, refreshType);
            FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_INVISIBLE_INTERCEPT);
            return ERR_OK;
        }
    }

    if (refreshType == Constants::REFRESHTYPE_VISIABLE) {
        FormDataMgr::GetInstance().GetRefreshType(formId, refreshType);
        HILOG_INFO("refreshType:%{public}d", refreshType);
        if (refreshType == Constants::REFRESHTYPE_NETWORKCHANGED) {
            isCountTimerRefresh = false;
        }
    }

    if (record.isSystemApp && refreshType != Constants::REFRESHTYPE_DEFAULT
        && refreshType != Constants::REFRESHTYPE_VISIABLE) {
        newWant.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, refreshType);
    } else {
        newWant.RemoveParam(Constants::PARAM_FORM_REFRESH_TYPE);
    }

    if (isCountTimerRefresh) {
        FormDataMgr::GetInstance().SetCountTimerRefresh(formId, true);
    }
    bool isFormProviderUpdate = want.GetBoolParam(Constants::FORM_ENABLE_UPDATE_REFRESH_KEY, false);
    DataProxyUpdate(formId, record, isFormProviderUpdate);
#ifdef SUPPORT_POWER
    newWant.RemoveParam(Constants::FORM_ENABLE_UPDATE_REFRESH_KEY);
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    bool collaborationScreenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsCollaborationScreenOn();
    bool isHicar = (record.moduleName == HICAR_FORM);
    if (!screenOnFlag && !collaborationScreenOnFlag && !isFormProviderUpdate && !isHicar) {
        UpdateWant(formId, want, record);
        FormDataMgr::GetInstance().UpdateFormRecord(formId, record);
        FormDataMgr::GetInstance().SetHostRefresh(formId, true);
        FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
        HILOG_INFO("screen off, set refresh flag, do not refresh now, formId:%{public}" PRId64 ".", formId);
        return ERR_OK;
    }
#endif

    bool needRefresh = IsNeedToFresh(record, formId, isVisibleToFresh);
    if (!needRefresh) {
        FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
        HILOG_ERROR("no one needReresh, set refresh flag, do not refresh now");
        return ERR_OK;
    }

    FormRecord refreshRecord = FormDataMgr::GetInstance().GetFormAbilityInfo(record);
    refreshRecord.isCountTimerRefresh = isCountTimerRefresh;
    refreshRecord.isTimerRefresh = isTimerRefresh;
    refreshRecord.isHostRefresh = record.isHostRefresh;
    return ConnectAmsForRefresh(formId, refreshRecord, newWant);
}

ErrCode FormProviderMgr::RefreshCheck(FormRecord &record, const int64_t formId, const Want &want)
{
    bool bGetRecord = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!bGetRecord) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    // get current userId
    int32_t currentActiveUserId = want.GetIntParam(Constants::PARAM_FORM_USER_ID, Constants::DEFAULT_PROVIDER_USER_ID);
    if (currentActiveUserId != record.providerUserId) {
        FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
        HILOG_ERROR("not current user, just set refresh flag, userId:%{public}d",
            record.providerUserId);
        return ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF;
    }

    if (!record.addFormFinish) {
        HILOG_ERROR("form is adding form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    return ERR_OK;
}

/**
 * @brief Connect provider ability for notify configuration changed.
 *
 * @param configuration The form id.
 * @param record Form data.
 * @param want The want of the form.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::ConnectForConfigUpdate(const AppExecFwk::Configuration &configuration,
    const FormRecord &record, const Want &want)
{
    HILOG_INFO("bundleName:%{public}s, abilityName:%{public}s",
        record.bundleName.c_str(), record.abilityName.c_str());
    sptr<IAbilityConnection> abilityConnection = new (std::nothrow) ConfigurationUpdateConnection(record.formId, want,
        record.bundleName, record.abilityName, configuration, record.providerUserId);
    if (abilityConnection == nullptr) {
        HILOG_ERROR("create FormRefreshConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.SetElementName(record.bundleName, record.abilityName);

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, abilityConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        if (errorCode == ERR_ECOLOGICAL_CONTROL_STATUS) {
            return ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED;
        }
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

/**
 * @brief Connect ams for refresh form
 *
 * @param formId The form id.
 * @param record Form data.
 * @param want The want of the form.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::ConnectAmsForRefresh(const int64_t formId, const FormRecord &record, const Want &want)
{
    HILOG_INFO("formId:%{public} " PRId64 ", bundleName:%{public}s, abilityName:%{public}s, "
        "needFreeInstall:%{public}d, isCountTimerRefresh:%{public}d, userId:%{public}d", formId,
        record.bundleName.c_str(), record.abilityName.c_str(), record.needFreeInstall, record.isCountTimerRefresh,
        record.providerUserId);

    sptr<IAbilityConnection> formRefreshConnection = new (std::nothrow) FormRefreshConnection(formId, want,
        record.bundleName, record.abilityName, record.needFreeInstall, record.providerUserId);
    if (formRefreshConnection == nullptr) {
        HILOG_ERROR("create FormRefreshConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(record.bundleName, record.abilityName);

    if (record.needFreeInstall) {
        return RebindByFreeInstall(record, connectWant, formRefreshConnection);
    }

    if (record.isCountTimerRefresh) {
        if (!FormTimerMgr::GetInstance().IsLimiterEnableRefresh(formId)) {
            HILOG_ERROR("timer refresh,already limit");
            return ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL;
        }
    }

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(connectWant, formRefreshConnection,
        record.providerUserId);
    if (errorCode != ERR_OK) {
        errorCode = (errorCode == ERR_ECOLOGICAL_CONTROL_STATUS) ?
            ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED : ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
        HILOG_ERROR("ConnectServiceAbility failed, errorCode:%{public}d", errorCode);
        FormEventReport::SendFormFailedEvent(FormEventName::CONNECT_FORM_ABILITY_FAILED, formId,
            record.bundleName, "", static_cast<int32_t>(ConnectFormAbilityErrorType::UPDATE_FORM_FAILED), errorCode);
        return errorCode;
    }

    if (record.isCountTimerRefresh) {
        IncreaseTimerRefreshCount(formId);
    }

    if (record.isTimerRefresh) {
        FormDataMgr::GetInstance().SetTimerRefresh(formId, false);
    }

    return ERR_OK;
}

/**
 * @brief Connect ability manager service for refresh app permission
 *
 * @param formId The form id.
 * @param want The want of the form.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::ConnectAmsForRefreshPermission(const int64_t formId, Want &want)
{
    HILOG_DEBUG("ConnectAmsForRefreshPermission start, form id:%{public}" PRId64 "", formId);
    if (!want.HasParameter(Constants::FORM_PERMISSION_NAME_KEY) ||
        !want.HasParameter(Constants::FORM_PERMISSION_GRANTED_KEY)) {
        HILOG_ERROR("permissionInfo not exist,form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormRecord record;
    bool result = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!result) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    want.RemoveParam(Constants::KEY_IS_TIMER);
    want.RemoveParam(Constants::KEY_TIMER_REFRESH);

    sptr<IAbilityConnection> formRefreshConnection = new (std::nothrow) FormRefreshConnection(formId, want,
        record.bundleName, record.abilityName, record.needFreeInstall, record.providerUserId);
    if (formRefreshConnection == nullptr) {
        HILOG_ERROR("create FormRefreshConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(record.bundleName, record.abilityName);

    if (record.needFreeInstall) {
        connectWant.AddFlags(Want::FLAG_INSTALL_ON_DEMAND | Want::FLAG_INSTALL_WITH_BACKGROUND_MODE);
        connectWant.SetModuleName(record.moduleName);
    }

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, formRefreshConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

/**
 * @brief Notify provider form delete.
 * @param formId The form id.
 * @param record Form information.
 * @return Function result and has other host flag.
 */
ErrCode FormProviderMgr::NotifyProviderFormDelete(const int64_t formId, const FormRecord &formRecord)
{
    if (formRecord.abilityName.empty()) {
        HILOG_ERROR("empty formRecord.abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("empty formRecord.bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("connectAbility,bundleName:%{public}s, abilityName:%{public}s",
        formRecord.bundleName.c_str(), formRecord.abilityName.c_str());
    sptr<IAbilityConnection> formDeleteConnection = new (std::nothrow) FormDeleteConnection(formId,
        formRecord.bundleName, formRecord.abilityName, formRecord.providerUserId);
    if (formDeleteConnection == nullptr) {
        HILOG_ERROR("create FormDeleteConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want want;
    want.SetElementName(formRecord.bundleName, formRecord.abilityName);
    want.SetFlags(Want::FLAG_ABILITY_FORM_ENABLED);

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formDeleteConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

/**
 * @brief Notify provider forms batch delete.
 * @param bundleName BundleName.
 * @param bundleName AbilityName.
 * @param formIds form id list.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::NotifyProviderFormsBatchDelete(const std::string &bundleName,
    const std::string &abilityName, const std::set<int64_t> &formIds, const int32_t userId)
{
    if (abilityName.empty()) {
        HILOG_ERROR("empty abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_DEBUG("bundleName:%{public}s, abilityName:%{public}s",
        bundleName.c_str(), abilityName.c_str());
    sptr<IAbilityConnection> batchDeleteConnection = new FormBatchDeleteConnection(formIds, bundleName, abilityName,
        userId);
    if (batchDeleteConnection == nullptr) {
        HILOG_ERROR("create FormBatchDeleteConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want want;
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    want.SetElementName(bundleName, abilityName);

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, batchDeleteConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}
/**
 * @brief Update form.
 * @param formId The form's id.
 * @param formProviderData form provider data.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::UpdateForm(const int64_t formId, const FormProviderInfo &formProviderInfo)
{
    // check exist and get the formRecord
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    return UpdateForm(formId, formRecord, formProviderInfo.GetFormData());
}
/**
 * handle for update form event from provider.
 *
 * @param formId The id of the form.
 * @param formRecord The form's record.
 * @param formProviderData provider form info.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::UpdateForm(const int64_t formId,
    FormRecord &formRecord, const FormProviderData &formProviderData)
{
    HILOG_INFO("imageDateState is %{public}d", formProviderData.GetImageDataState());
    if (formRecord.versionUpgrade) {
        formRecord.formProviderInfo.SetFormData(formProviderData);
        formRecord.formProviderInfo.SetUpgradeFlg(true);
    } else {
        nlohmann::json addJsonData = formProviderData.GetData();
        formRecord.formProviderInfo.MergeData(addJsonData);
        // merge image
        auto formData = formRecord.formProviderInfo.GetFormData();
        formData.SetImageDataState(formProviderData.GetImageDataState());
        formData.SetImageDataMap(formProviderData.GetImageDataMap());
        formRecord.formProviderInfo.SetFormData(formData);
    }

    // formRecord init
    formRecord.isInited = true;
    formRecord.needRefresh = false;
    FormDataMgr::GetInstance().SetFormCacheInited(formId, true);

    // update form for host clients
    FormDataMgr::GetInstance().UpdateHostNeedRefresh(formId, true);

#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    if (screenOnFlag) {
        if (FormDataMgr::GetInstance().UpdateHostForm(formId, formRecord)) {
            FormDataMgr::GetInstance().SetVersionUpgrade(formId, false);
            formRecord.formProviderInfo.SetUpgradeFlg(false);
        }
    }
    HILOG_DEBUG("screenOn:%{public}d", screenOnFlag);
#endif

    if (formRecord.formProviderInfo.NeedCache()) {
        HILOG_INFO("updateJsForm, data is less than 1k, cache data");
        FormCacheMgr::GetInstance().AddData(formId, formRecord.formProviderInfo.GetFormData());
    } else {
        FormCacheMgr::GetInstance().DeleteData(formId);
    }

    // the update form is successfully
    return ERR_OK;
}
/**
 * @brief Process js message event.
 * @param formId Indicates the unique id of form.
 * @param record Form record.
 * @param want information passed to supplier.
 * @return Returns true if execute success, false otherwise.
 */
int FormProviderMgr::MessageEvent(const int64_t formId, const FormRecord &record, const Want &want)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);

#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    bool collaborationScreenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsCollaborationScreenOn();
    bool isHicar = (record.moduleName == HICAR_FORM);
    if (!screenOnFlag && !collaborationScreenOnFlag && !isHicar) {
        HILOG_WARN("screen off now");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
#endif

    sptr<IAbilityConnection> formMsgEventConnection = new (std::nothrow) FormMsgEventConnection(formId, want,
        record.bundleName, record.abilityName, record.providerUserId);
    if (formMsgEventConnection == nullptr) {
        HILOG_ERROR("create FormMsgEventConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(record.bundleName, record.abilityName);

    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(connectWant,
        formMsgEventConnection, record.providerUserId);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

/**
 * @brief Connect ams for refresh form
 *
 * @param formId The form id.
 * @param record Form data.
 * @param want The want of the form.
 * @return Returns ERR_OK on success, others on failure.
 */
 ErrCode FormProviderMgr::ConnectAmsChangeLocation(const int64_t formId, const FormRecord &record,
    const Want &want)
{
    HILOG_INFO("formId:%{public} " PRId64 ", bundleName:%{public}s, abilityName:%{public}s", formId,
        record.bundleName.c_str(), record.abilityName.c_str());

    sptr<IAbilityConnection> formLocationConnection = new (std::nothrow) FormLocationConnection(formId, want,
        record.bundleName, record.abilityName, record.providerUserId);
    if (formLocationConnection == nullptr) {
        HILOG_ERROR("create FormLocationConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(record.bundleName, record.abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, formLocationConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        if (errorCode == ERR_ECOLOGICAL_CONTROL_STATUS) {
            return ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED;
        }
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

/**
 * @brief Increase the timer refresh count.
 *
 * @param formId The form id.
 */
void FormProviderMgr::IncreaseTimerRefreshCount(const int64_t formId)
{
    FormRecord record;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, record)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return;
    }

    if (record.isCountTimerRefresh) {
        FormDataMgr::GetInstance().SetCountTimerRefresh(formId, false);
        FormTimerMgr::GetInstance().IncreaseRefreshCount(formId);
    }
}

/**
 * @brief Acquire form state.
 * @param state form state.
 * @param provider provider info.
 * @param wantArg The want of onAcquireFormState.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::AcquireFormStateBack(FormState state, const std::string& provider, const Want &wantArg)
{
    HILOG_DEBUG("AcquireFormState start:%{public}d, provider:%{public}s", state, provider.c_str());
    FormDataMgr::GetInstance().AcquireFormStateBack(state, provider, wantArg);
    return ERR_OK;
}

ErrCode FormProviderMgr::AcquireFormDataBack(const AAFwk::WantParams &wantParams,
    int64_t requestCode)
{
    HILOG_DEBUG("start");
    FormDataMgr::GetInstance().AcquireFormDataBack(wantParams, requestCode);
    return ERR_OK;
}

bool FormProviderMgr::IsNeedToFresh(FormRecord &record, int64_t formId, bool isVisibleToFresh)
{
    bool isEnableRefresh = FormDataMgr::GetInstance().IsEnableRefresh(formId);
    HILOG_DEBUG("isEnableRefresh is %{public}d", isEnableRefresh);
    if (isEnableRefresh) {
        return true;
    }

    HILOG_DEBUG("isVisibleToFresh is %{public}d, record.isVisible is %{public}d", isVisibleToFresh, record.isVisible);
    if (isVisibleToFresh) {
        if (!record.isVisible) {
            FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_INVISIBLE_INTERCEPT);
        }
        return record.isVisible;
    }

    bool isEnableUpdate = FormDataMgr::GetInstance().IsEnableUpdate(formId);
    HILOG_DEBUG("isEnableUpdate is %{public}d", isEnableUpdate);
    return isEnableUpdate;
}

bool FormProviderMgr::IsFormCached(const FormRecord &record)
{
    if (record.versionUpgrade) {
        return false;
    }
    return FormCacheMgr::GetInstance().NeedAcquireProviderData(record.formId);
}

ErrCode FormProviderMgr::RebindByFreeInstall(const FormRecord &record, Want &want,
    const sptr<AAFwk::IAbilityConnection> formRefreshConnection)
{
    HILOG_INFO("start");
    want.AddFlags(Want::FLAG_INSTALL_ON_DEMAND | Want::FLAG_INSTALL_WITH_BACKGROUND_MODE);
    want.SetModuleName(record.moduleName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formRefreshConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed, err:%{public}d", errorCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

/**
 * @brief Connect provider for update form size.
 * @param newDimension The dimension value to be updated.
 * @param newRect The rect value to be updated.
 * @param formRecord The record of the form.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormProviderMgr::ConnectAmsUpdateSize(const int32_t newDimension,
    const Rect &newRect, const FormRecord &record)
{
    HILOG_INFO("formId:%{public} " PRId64, record.formId);
    sptr<IAbilityConnection> formUpdateSizeConnection = new (std::nothrow) FormUpdateSizeConnection(
        record.formId, record.bundleName, record.abilityName, newDimension, newRect, record.providerUserId);
    if (formUpdateSizeConnection == nullptr) {
        HILOG_ERROR("create FormUpdateSizeConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(record.bundleName, record.abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, formUpdateSizeConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        if (errorCode == ERR_ECOLOGICAL_CONTROL_STATUS) {
            return ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED;
        }
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
