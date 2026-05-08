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
#include "form_mgr/form_data_adapter.h"

#include <chrono>

#include "ability_manager_errors.h"
#include "bundle_info.h"
#include "form_event_report.h"
#include "form_event_report_define.h"
#include "form_js_info.h"
#include "form_major_info.h"
#include "form_provider_data.h"
#include "form_provider_data_proxy.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"
#include "want_params.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_report.h"
#include "common/util/form_task_common.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "form_constants.h"
#include "form_host/form_host_record.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr/form_mgr_queue.h"
#include "form_mgr_errors.h"
#include "form_provider/connection/form_acquire_connection.h"
#include "common/connection/form_ability_connection_reporter.h"
#include "form_refresh/form_refresh_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_render/form_render_mgr.h"

#include "form_mgr/form_adapter_constants.h"

namespace OHOS {
namespace AppExecFwk {
using namespace FormAdapterConstants;

namespace {
constexpr int32_t ESTIMATED_REPORT_STR_SIZE_PER_FORM = 50;
}

FormDataAdapter::FormDataAdapter()
{
    HILOG_DEBUG("FormDataAdapter created");
}

FormDataAdapter::~FormDataAdapter()
{
}

ErrCode FormDataAdapter::UpdateTimer(const int64_t formId, const FormRecord &record)
{
    ErrCode errorCode = FormCommonAdapter::GetInstance().AddFormTimer(record);
    if (errorCode != ERR_OK) {
        return errorCode;
    }
    if (!record.formTempFlag) {
        return FormDbCache::GetInstance().UpdateDBRecord(formId, record);
    }
    return ERR_OK;
}

int FormDataAdapter::UpdateForm(const int64_t formId, const int32_t callingUid,
    const FormProviderData &formProviderData,
    const std::vector<FormDataProxy> &formDataProxies)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("formId:%{public}" PRId64, formId);

    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    int ret = ERR_OK;
    RefreshData data;
    data.formId = matchedFormId;
    data.record = formRecord;
    data.callingUid = callingUid;
    data.providerData = formProviderData;
    ret = FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_DATA);

    if (!formDataProxies.empty()) {
        FormDataProxyMgr::GetInstance().UpdateSubscribeFormData(matchedFormId, formDataProxies);
    }
    return ret;
}

int FormDataAdapter::RequestForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Want addFormWant(want);
    bool isNeedAddForm = want.GetBoolParam(Constants::IS_NEED_ADDFORM_ON_REQUEST, false);
    addFormWant.RemoveParam(Constants::IS_NEED_ADDFORM_ON_REQUEST);
    addFormWant.RemoveParam(Constants::PARAM_FORM_DISABLE_UIFIRST_KEY);
    Want updateFormWant(addFormWant);
    updateFormWant.RemoveParam(Constants::PARAM_FORM_WIDTH_KEY);
    updateFormWant.RemoveParam(Constants::PARAM_FORM_HEIGHT_KEY);
    updateFormWant.RemoveParam(Constants::PARAM_FORM_DIMENSION_KEY);
    updateFormWant.RemoveParam(Constants::PARAM_FORM_BORDER_WIDTH_KEY);

    if (formId <= 0 || callerToken == nullptr) {
        HILOG_ERROR("invalid formId or callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (isNeedAddForm) {
        updateFormWant.SetParam(Constants::UPDATE_FORM_REASON_KEY, Constants::FormUpdateReason::FORM_NODE_REUSE);
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    UpdateFormRenderParam(matchedFormId, callerToken, want);
    FormDataMgr::GetInstance().UpdateFormHostParams(formId, want);
    FormRecord record;
    bool result = FormDataMgr::GetInstance().GetFormRecord(matchedFormId, record);
    if (!result) {
        HILOG_ERROR("not exist such formId:%{public}" PRId64 ".", matchedFormId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    RefreshData data;
    data.callingUid = IPCSkeleton::GetCallingUid();
    data.formId = matchedFormId;
    data.record = record;
    data.callerToken = callerToken;
    data.want = updateFormWant;
    bool needAcquireProviderData = FormCacheMgr::GetInstance().NeedAcquireProviderData(formId);
    HILOG_INFO("formId:%{public}" PRId64 ", isNeedAddForm:%{public}d, needAcquireProviderData:%{public}d, "
        "needRefresh:%{public}d.", formId, isNeedAddForm, needAcquireProviderData, record.needRefresh);
    if (isNeedAddForm && (needAcquireProviderData || record.needRefresh)) {
        ErrCode errCode = AcquireProviderFormInfoByFormRecord(record, addFormWant.GetParams());
        auto delayRefreshForm = [data]() mutable {
            FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_HOST);
        };
        FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, delayRefreshForm);
        if (errCode != ERR_OK) {
            HILOG_ERROR("AcquireProviderFormInfoByFormRecord failed, formId:%{public}" PRId64, formId);
        }
        return errCode;
    }

    return FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_HOST);
}

int FormDataAdapter::UpdateFormSize(const int64_t &formId,
    float width, float height, float borderWidth, float formViewScale)
{
    FormRenderMgr::GetInstance().UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    return ERR_OK;
}

ErrCode FormDataAdapter::UpdateFormSize(const int64_t formId,
    const int32_t newDimension, const Rect &newRect)
{
    HILOG_INFO("call, formId:%{public} " PRId64, formId);
    FormRecord record;
    bool result = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!result) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    FormInfo formInfo;
    ErrCode errCode = FormCommonAdapter::GetInstance().GetFormInfoByFormRecord(record, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail get form info:%{public}" PRId64 "", formId);
        return errCode;
    }
    if (!FormCommonAdapter::GetInstance().IsDimensionValid(formInfo, newDimension)) {
        HILOG_ERROR("Invalid dimension");
        return ERR_APPEXECFWK_FORM_DIMENSION_ERROR;
    }
    errCode = FormProviderMgr::GetInstance().ConnectAmsUpdateSize(newDimension, newRect, record);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail connect provider:%{public}" PRId64 "", formId);
        return errCode;
    }
    return FormDataMgr::GetInstance().SetSpecification(formId, newDimension);
}

int FormDataAdapter::EnableUpdateForm(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("enableUpdateForm");
    return HandleUpdateFormFlag(formIds, callerToken, true, false);
}

int FormDataAdapter::DisableUpdateForm(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("disableUpdateForm");
    return HandleUpdateFormFlag(formIds, callerToken, false, false);
}

ErrCode FormDataAdapter::HandleUpdateFormFlag(const std::vector<int64_t> &formIds,
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
        int32_t userId = FormCommonAdapter::GetInstance().GetCallingUserId();
        for (const int64_t id : refreshForms) {
            HILOG_DEBUG("formRecord need refresh:%{public}" PRId64 "", id);
            Want want;
            want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
            FormProviderMgr::GetInstance().RefreshForm(id, want, false);
        }
    }
    return errCode;
}

ErrCode FormDataAdapter::BatchRefreshForms(const int32_t formRefreshType)
{
    HILOG_INFO("BatchRefreshForms type:%{public}d", formRefreshType);
    std::vector<FormRecord> visibleFormRecords;
    std::vector<FormRecord> invisibleFormRecords;
    FormDataMgr::GetInstance().GetRecordsByFormType(formRefreshType, visibleFormRecords, invisibleFormRecords);
    HILOG_INFO("getRecords visible size:%{public}zu, invisible size:%{public}zu",
        visibleFormRecords.size(), invisibleFormRecords.size());
    std::vector<RefreshData> batch;
    for (auto &formRecord : visibleFormRecords) {
        formRecord.isCountTimerRefresh = false;
        formRecord.isTimerRefresh = false;
        RefreshData data;
        data.record = formRecord;
        data.formId = formRecord.formId;
        batch.push_back(data);
    }
    for (auto &formRecord : invisibleFormRecords) {
        formRecord.isCountTimerRefresh = false;
        formRecord.isTimerRefresh = false;
        RefreshData data;
        data.record = formRecord;
        data.formId = formRecord.formId;
        batch.push_back(data);
    }
    FormRefreshMgr::GetInstance().BatchRequestRefresh(TYPE_FORCE, StaggerStrategyType::DEFAULT, batch);
    return ERR_OK;
}

int FormDataAdapter::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_INFO("formId:%{public}" PRId64 ", nextTime:%{public}" PRId64, formId, nextTime);

    if (formId <= 0) {
        HILOG_ERROR("invalid formId");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);
    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not found in formRecord");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    RefreshData data;
    data.callingUid = IPCSkeleton::GetCallingUid();
    data.formId = matchedFormId;
    data.record = formRecord;
    data.nextTime = nextTime;

    return FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_NEXT_TIME);
}

void FormDataAdapter::UpdateFormRenderParam(const int64_t formId, const sptr<IRemoteObject> &callerToken,
    const Want &want)
{
    if (want.GetParams().HasParam(Constants::PARAM_FORM_DISABLE_UIFIRST_KEY)) {
        bool isEnable = !want.GetBoolParam(Constants::PARAM_FORM_DISABLE_UIFIRST_KEY, false);
        FormRenderMgr::GetInstance().SetRenderGroupEnableFlag(formId, isEnable);
    }

    FormUpgradeInfo formUpgradeInfo;
    FormDataMgr::GetInstance().GetFormUpgradeInfo(formId, formUpgradeInfo);
    FormHostRecord hostRecord;
    bool hasRecord = FormDataMgr::GetInstance().GetMatchedHostClient(callerToken, hostRecord);
    bool hasTransparencyKey = want.GetParams().HasParam(Constants::PARAM_FORM_TRANSPARENCY_KEY);
    std::string curTransparencyColor = Constants::DEFAULT_TRANSPARENCY_COLOR;
    std::string cacheTransparencyColor = hostRecord.GetTransparentFormColor(formId);
    if (hasTransparencyKey) {
        curTransparencyColor = want.GetStringParam(Constants::PARAM_FORM_TRANSPARENCY_KEY);
        formUpgradeInfo.transparencyColor = curTransparencyColor;
        FormDataMgr::GetInstance().SetHostTransparentFormColor(formId, curTransparencyColor);
    } else {
        formUpgradeInfo.transparencyColor.clear();
        FormDataMgr::GetInstance().DelHostTransparentFormColor(formId);
    }
    HILOG_INFO("FormId:%{public}" PRId64 " curTransparencyColor: %{public}s, cacheTransparencyColor: %{public}s",
        formId, curTransparencyColor.c_str(), cacheTransparencyColor.c_str());
    FormDataMgr::GetInstance().UpdateFormUpgradeInfo(formId, formUpgradeInfo);

    if (hasRecord && hasTransparencyKey && curTransparencyColor != cacheTransparencyColor) {
        Want renderWant;
        renderWant.SetParam(Constants::PARAM_FORM_TRANSPARENCY_KEY, curTransparencyColor);
        FormRenderMgr::GetInstance().SetRenderGroupParams(formId, renderWant);
    }
}

int FormDataAdapter::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    HILOG_INFO("UpdateFormLocation formId = %{public}" PRId64 " formLocation = %{public}d",
        formId, formLocation);

    int64_t matchedFormId = FormDataMgr::GetInstance().FindMatchedFormId(formId);

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("not exist such form, formId = %{public}" PRId64 " formLocation = %{public}d",
            formId, formLocation);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    bool isFormLocationChange = (int32_t)formRecord.formLocation != formLocation;
    if (isFormLocationChange || (formRecord.isSystemApp && isRequestPublishFormWithSnapshot)) {
        HILOG_INFO("UpdateFormLocation isFormLocationChange = %{public}d, isSystemApp = %{public}d, "
            "isRequestPublishFormWithSnapshot = %{public}d", isFormLocationChange,
            formRecord.isSystemApp, isRequestPublishFormWithSnapshot);
        Want locationWant;
        locationWant.SetParam(Constants::FORM_LOCATION_KEY, formLocation);
        FormProviderMgr::GetInstance().ConnectAmsChangeLocation(formId, formRecord, locationWant);
        UpdateTimer(matchedFormId, formRecord);
        FormDataMgr::GetInstance().UpdateFormLocation(matchedFormId, formLocation);
        if (!formRecord.formTempFlag) {
            auto ret = FormCommonAdapter::GetInstance().HandleFormAddObserver(matchedFormId);
            if (ret != ERR_OK) {
                return ret;
            }
            return FormDbCache::GetInstance().UpdateFormLocation(matchedFormId, formLocation);
        }
    }
    return ERR_OK;
}

ErrCode FormDataAdapter::AcquireProviderFormInfoByFormRecord(const FormRecord &formRecord, const WantParams &wantParams)
{
    Want addFormWant;
    addFormWant.SetParams(wantParams);

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    BundleInfo bundleInfo;
    ErrCode errCode = FormBmsHelper::GetInstance().GetBundleInfoV9(formRecord.bundleName,
        formRecord.userId, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get bundleInfo failed");
        return errCode;
    }

    FormInfo formInfo;
    errCode = FormInfoMgr::GetInstance().GetFormsInfoByRecord(formRecord, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get formInfo failed");
        return errCode;
    }

    FormItemInfo formItemInfo;
    formItemInfo.SetFormId(formRecord.formId);
    formItemInfo.SetSpecificationId(addFormWant.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY,
        formInfo.defaultDimension));
    errCode = FormCommonAdapter::GetInstance().CreateFormItemInfo(bundleInfo, formInfo, formItemInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get form config info failed. formId: %{public}" PRId64 " code: %{public}d",
            formRecord.formId, errCode);
        return errCode;
    }

    addFormWant.SetParam(Constants::PARAM_DYNAMIC_NAME_KEY, formRecord.isDynamic);
    addFormWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, formRecord.moduleName);
    addFormWant.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, formRecord.formTempFlag);
    addFormWant.SetParam(Constants::PARAM_FORM_OBSCURED_KEY, formRecord.protectForm || !formRecord.enableForm);
    addFormWant.SetParam(Constants::PARAM_FORM_RENDERINGMODE_KEY, static_cast<int>(formRecord.renderingMode));
    addFormWant.SetParam(Constants::PARAM_FONT_FOLLOW_SYSTEM_KEY, formInfo.fontScaleFollowSystem);
    addFormWant.SetParam(Constants::PARAM_FORM_ENABLE_BLUR_BACKGROUND_KEY, formInfo.enableBlurBackground);
    return AcquireProviderFormInfoAsync(formRecord.formId, formItemInfo, addFormWant.GetParams());
}

ErrCode FormDataAdapter::AcquireProviderFormInfoAsync(const int64_t formId,
    const FormItemInfo &info, const WantParams &wantParams)
{
    std::string providerBundleName = info.GetProviderBundleName();
    if (!info.IsEnableForm()) {
        HILOG_INFO("Bundle:%{public}s forbidden", providerBundleName.c_str());
        FormDataMgr::GetInstance().SetRefreshDuringDisableForm(formId, true);

        auto task = [formId, newInfo = info, newWant = wantParams]() {
            FormDataAdapter::GetInstance().InnerAcquireProviderFormInfoAsync(formId, newInfo, newWant);
        };
        FormRenderMgr::GetInstance().AddAcquireProviderForbiddenTask(info.GetProviderBundleName(), formId, task);
        return ERR_OK;
    }

    if (FormRenderMgr::GetInstance().GetIsSecondMounted()) {
        HILOG_INFO("The authentication status is true");
        return InnerAcquireProviderFormInfoAsync(formId, info, wantParams);
    }

    HILOG_INFO("The currentUser not unlocked");
    FormRecord record;
    bool result = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!result) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    auto task = [formId, newInfo = info, newWant = wantParams]() {
        FormDataAdapter::GetInstance().InnerAcquireProviderFormInfoAsync(formId, newInfo, newWant);
    };
    FormRenderMgr::GetInstance().AddAcquireProviderFormInfoTask(record.providerUserId, task);
    return ERR_OK;
}

ErrCode FormDataAdapter::InnerAcquireProviderFormInfoAsync(const int64_t formId,
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

    FormRecord record;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, record)) {
        HILOG_ERROR("not found in formRecord");
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    Want want;
    want.SetElementName(info.GetProviderBundleName(), info.GetAbilityName());
    if (!info.GetModuleName().empty()) {
        want.SetModuleName(info.GetModuleName());
    }
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(
        want, formAcquireConnection, record.providerUserId);
    FormReport::GetInstance().SetStartBindTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    if (errorCode != ERR_OK && errorCode != ERR_ECOLOGICAL_CONTROL_STATUS) {
        HILOG_ERROR("ConnectServiceAbility failed, errorCode:%{public}d", errorCode);
        FormEventReport::SendFormFailedEvent(FormEventName::CONNECT_FORM_ABILITY_FAILED, formId,
            record.bundleName, "", static_cast<int32_t>(ConnectFormAbilityErrorType::ACQUIRE_FORM_FAILED), errorCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

ErrCode FormDataAdapter::ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams)
{
    int64_t formId = info.GetFormId();
    HILOG_INFO("reconnect bundleName:%{public}s, formId:%{public}" PRId64, info.GetProviderBundleName().c_str(),
        formId);
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    auto iter = formReconnectMap_.find(formId);
    if (iter == formReconnectMap_.end()) {
        iter = formReconnectMap_.emplace(formId, 0).first;
    }
    iter->second++;
    int32_t delayAcquireProviderFormInfoTime = 0;
    if (iter->second < MAX_RECONNECT_NUMS) {
        delayAcquireProviderFormInfoTime = iter->second * RECONNECT_RETRY_DELAY_TIME;
    } else if (iter->second == MAX_RECONNECT_NUMS) {
        delayAcquireProviderFormInfoTime = LAST_RECONNECT_RETRY_DELAY_TIME;
    } else {
        formReconnectMap_.erase(formId);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    auto delayAcquireProviderFormInfo = [info, wantParams]() {
        FormDataAdapter::GetInstance().AcquireProviderFormInfoAsync(info.GetFormId(), info, wantParams);
    };
    HILOG_WARN("reconnect formId:%{public}" PRId64 ", schedule retry after %{public}d ms", formId,
        delayAcquireProviderFormInfoTime);
    FormMgrQueue::GetInstance().ScheduleTask(delayAcquireProviderFormInfoTime, delayAcquireProviderFormInfo);
    return ERR_OK;
}

void FormDataAdapter::ClearReconnectNum(int64_t formId)
{
    std::lock_guard<std::mutex> lock(reconnectMutex_);
    formReconnectMap_.erase(formId);
}

ErrCode FormDataAdapter::ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms)
{
    HILOG_DEBUG("call");
    pid_t callingPid = IPCSkeleton::GetCallingPid();
    if (!CheckUIAbilityContext(callingPid)) {
        HILOG_ERROR("check uiAbility failed");
        return ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY;
    }

    int callingUid = IPCSkeleton::GetCallingUid();
    std::vector<RefreshData> batch;
    for (const FormRecord &formRecord : refreshForms) {
        RefreshData data;
        data.record = formRecord;
        data.formId = formRecord.formId;
        data.callingUid = callingUid;
        batch.push_back(data);
    }
    FormRefreshMgr::GetInstance().BatchRequestRefresh(TYPE_PROVIDER, StaggerStrategyType::DEFAULT, batch);
    for (const auto &data : batch) {
        if (data.errorCode == ERR_OK) {
            reloadNum++;
        }
    }
    return ERR_OK;
}

bool FormDataAdapter::CheckUIAbilityContext(const pid_t pid)
{
    auto appMgrProxy = FormCommonAdapter::GetInstance().GetAppMgr();
    if (!appMgrProxy) {
        HILOG_ERROR("Get app mgr failed");
        return false;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    OHOS::AppExecFwk::RunningProcessInfo info;
    int32_t result = appMgrProxy->GetRunningProcessInfoByPid(pid, info);
    IPCSkeleton::SetCallingIdentity(identity);
    if (result != ERR_OK) {
        HILOG_ERROR("GetRunningProcessInfoByPid failed");
        return false;
    }
    if (info.extensionType_ == ExtensionAbilityType::FORM) {
        HILOG_ERROR("extensionType_ is not uiability");
        return false;
    }
    return true;
}

bool FormDataAdapter::IsDeleteCacheInUpgradeScene(const FormRecord &record)
{
    if (record.isDataProxy) {
        return false;
    }
    FormInfo formInfo;
    ErrCode errCode = FormInfoMgr::GetInstance().GetFormsInfoByRecord(record, formInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get formInfo failed");
        return true;
    }
    if (record.isSystemApp && !FormInfoMgr::GetInstance().IsDeleteCacheInUpgradeScene(formInfo)) {
        return false;
    }
    return true;
}

int32_t FormDataAdapter::OnNotifyRefreshForm(const int64_t &formId)
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
        int32_t userId = FormCommonAdapter::GetInstance().GetCallingUserId();
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

ErrCode FormDataAdapter::UpdateFormByCondition(int32_t type)
{
    HILOG_INFO("UpdateFormByCondition type:%{public}d", type);
    std::vector<FormRecord> formInfos;
    if (!FormDataMgr::GetInstance().GetFormRecordByCondition(type, formInfos)) {
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    std::string reportStr;
    reportStr.reserve(formInfos.size() * ESTIMATED_REPORT_STR_SIZE_PER_FORM);

    std::vector<RefreshData> batch;
    for (const FormRecord& formRecord : formInfos) {
        RefreshData data;
        data.formId = formRecord.formId;
        data.record = formRecord;
        batch.push_back(data);
        reportStr.append(formRecord.bundleName).append("_").append(formRecord.formName);
    }
    FormRefreshMgr::GetInstance().BatchRequestRefresh(TYPE_NETWORK, StaggerStrategyType::VISIBLE_DELAY, batch);
    std::string subStr = reportStr.substr(0, std::min((int)reportStr.size(), 30));
    HILOG_INFO("UpdateFormByCondition reportStr:%{public}s", subStr.c_str());
    NewFormEventInfo eventInfo;
    eventInfo.conditionType = static_cast<int32_t>(type);
    eventInfo.bundleAndFormName = reportStr;
    FormEventReport::SendConditonUpdateFormEvent(FormEventName::CONDITION_UPDATE_FORM,
        HiSysEventType::BEHAVIOR, eventInfo);

    return ERR_OK;
}

void FormDataAdapter::DelayRefreshFormsOnAppUpgrade(const std::vector<FormRecord> &updatedForms, const Want &want)
{
    HILOG_INFO("start");
    auto delayRefreshForms = [updatedForms, want]() {
        for (const auto &updatedForm : updatedForms) {
            FormDataAdapter::GetInstance().UpdateFormRenderParamsAfterReload(updatedForm.formId);
            RefreshData data;
            data.formId = updatedForm.formId;
            data.record = updatedForm;
            data.want = want;
            ErrCode errCode = FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_APP_UPGRADE);
            if (errCode == ERR_APPEXECFWK_FORM_GET_AMSCONNECT_FAILED) {
                HILOG_WARN("RefreshForm failed one time, PostRefreshFormTask to retry. form %{public}" PRId64 "",
                    updatedForm.formId);
                FormDataAdapter::GetInstance().PostEnterpriseAppInstallFailedRetryTask(updatedForm, want);
            }
        }
    };
    FormMgrQueue::GetInstance().ScheduleTask(PROVIDER_UPDATE_REFRESH_FORMS_TASK_DELAY_TIME, delayRefreshForms);
    HILOG_INFO("end");
}

void FormDataAdapter::PostEnterpriseAppInstallFailedRetryTask(const FormRecord &record, const Want &want)
{
    HILOG_INFO("start");
    auto refreshForm = [record, want]() {
        RefreshData data;
        data.formId = record.formId;
        data.record = record;
        data.want = want;
        FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_APP_UPGRADE);
    };
    FormMgrQueue::GetInstance().ScheduleTask(ENTERPRISE_APP_INSTALL_FAILED_DELAY_TIME, refreshForm);
    HILOG_INFO("end");
}

void FormDataAdapter::UpdateReUpdateFormMap(const int64_t formId)
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

void FormDataAdapter::SetReUpdateFormMap(const int64_t formId)
{
    std::lock_guard<std::mutex> lock(reUpdateFormMapMutex_);
    auto search = reUpdateFormMap_.find(formId);
    if (search != reUpdateFormMap_.end()) {
        search->second.second = true;
    }
}

void FormDataAdapter::UpdateFormRenderParamsAfterReload(const int64_t formId)
{
    Want renderWant;
    FormUpgradeInfo formUpgradeInfo;
    bool hasFormRecord = FormDataMgr::GetInstance().GetFormUpgradeInfo(formId, formUpgradeInfo);
    if (!hasFormRecord) {
        HILOG_ERROR("FormId:%{public}" PRId64 " form record not found.", formId);
        return;
    }
    std::string transparencyColor = formUpgradeInfo.transparencyColor;
    if (!transparencyColor.empty()) {
        renderWant.SetParam(Constants::PARAM_FORM_TRANSPARENCY_KEY, transparencyColor);
    }
    if (formUpgradeInfo.enableBlurBackground) {
        renderWant.SetParam(Constants::PARAM_FORM_ENABLE_BLUR_BACKGROUND_KEY, true);
    }
    HILOG_INFO("Need to set transparencyColor: %{public}s, enableBlurBackground: %{public}d",
        transparencyColor.c_str(), formUpgradeInfo.enableBlurBackground);
    FormRenderMgr::GetInstance().SetRenderGroupParams(formId, renderWant);
}

int64_t FormDataAdapter::GetUpdateDurationFromAdditionalInfo(const std::string &additionalInfo)
{
    if (additionalInfo.empty()) {
        return 0;
    }

    auto durationArray = FormUtil::ParseFormUpdateLevels(additionalInfo);
    if (durationArray.empty()) {
        return 0;
    }
    return static_cast<int64_t>(durationArray.back()) * Constants::TIME_CONVERSION;
}

void FormDataAdapter::DeleteInvalidFormCacheIfNeed()
{
    auto deleteInvalidFormCache = []() {
        bool isDirtyDataCleaned = false;
        if (FormCacheMgr::GetInstance().IsDirtyDataCleaned()) {
            HILOG_INFO("no dirty data");
            return;
        }
        FormCacheMgr::GetInstance().SetIsDirtyDataCleaned();
        std::unordered_set<int64_t> invalidIds;
        if (!FormCacheMgr::GetInstance().GetFormCacheIds(invalidIds)) {
            HILOG_WARN("no find cache data");
            return;
        }
        std::vector<FormDBInfo> formDBInfos;
        FormDbCache::GetInstance().GetAllFormInfo(formDBInfos);
        for (const auto &validFormInfo : formDBInfos) {
            auto iter = invalidIds.find(validFormInfo.formId);
            if (iter != invalidIds.end()) {
                invalidIds.erase(iter);
            }
        }
        std::for_each(invalidIds.begin(), invalidIds.end(), [](const int64_t invalidId) {
            HILOG_INFO("delete invalid formId: %{public}" PRId64, invalidId);
            FormCacheMgr::GetInstance().DeleteData(invalidId);
        });
    };
    FormMgrQueue::GetInstance().ScheduleTask(0, deleteInvalidFormCache);
}

} // namespace AppExecFwk
} // namespace OHOS