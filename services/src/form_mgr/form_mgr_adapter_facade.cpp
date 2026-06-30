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

#include "form_mgr/form_mgr_adapter_facade.h"

#include "form_constants.h"
#include "ipc_skeleton.h"

#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "form_mgr/form_callback_adapter.h"
#include "form_mgr/form_debug_adapter.h"
#include "form_mgr/form_publish_adapter.h"
#include "form_mgr/form_visibility_adapter.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormMgrAdapterFacade::FormMgrAdapterFacade()
{
    HILOG_DEBUG("FormMgrAdapterFacade created");
}

FormMgrAdapterFacade::~FormMgrAdapterFacade()
{
}

void FormMgrAdapterFacade::Init()
{
    HILOG_INFO("Init called");
    // Note: Individual adapters handle their own initialization internally.
    // This method is provided for API compatibility with FormMgrAdapter.

    // Clean up invalid form cache (only executes once)
    FormDataAdapter::GetInstance().DeleteInvalidFormCacheIfNeed();
    // Load visibleNotifyDelayTime
    FormVisibilityAdapter::GetInstance().Init();
}

ErrCode FormMgrAdapterFacade::QueryPublishFormToHost(Want &want)
{
    return FormPublishAdapter::GetInstance().QueryPublishFormToHost(want);
}

ErrCode FormMgrAdapterFacade::QueryPublishFormToHost(Want &want, int32_t userId)
{
    return FormPublishAdapter::GetInstance().QueryPublishFormToHost(want, userId);
}

ErrCode FormMgrAdapterFacade::RequestPublishFormCommon(Want &want, int32_t userId, int64_t &formId)
{
    return FormPublishAdapter::GetInstance().RequestPublishFormCommon(want, userId, formId);
}

ErrCode FormMgrAdapterFacade::RequestPublishFormCrossUser(Want &want, int32_t userId, int64_t &formId)
{
    return FormPublishAdapter::GetInstance().RequestPublishFormCrossUser(want, userId, formId);
}

ErrCode FormMgrAdapterFacade::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    return FormPublishAdapter::GetInstance().RequestPublishForm(want, withFormBindingData, formBindingData, formId,
        formDataProxies, needCheckFormPermission);
}

ErrCode FormMgrAdapterFacade::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    return FormPublishAdapter::GetInstance().SetPublishFormResult(formId, errorCodeInfo);
}

ErrCode FormMgrAdapterFacade::AcquireAddFormResult(const int64_t formId)
{
    return FormPublishAdapter::GetInstance().AcquireAddFormResult(formId);
}

bool FormMgrAdapterFacade::IsRequestPublishFormSupported()
{
    return FormPublishAdapter::GetInstance().IsRequestPublishFormSupported();
}

int FormMgrAdapterFacade::AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo)
{
    return FormLifecycleAdapter::GetInstance().AddForm(formId, want, callerToken, formInfo);
}

int FormMgrAdapterFacade::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    return FormLifecycleAdapter::GetInstance().CreateForm(want, runningFormInfo);
}

int FormMgrAdapterFacade::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    HILOG_INFO("StopRenderingForm called, formId:%{public}" PRId64, formId);
    return FormLifecycleAdapter::GetInstance().StopRenderingForm(formId, compId);
}

int FormMgrAdapterFacade::DeleteInvalidForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    HILOG_INFO("DeleteInvalidForms called, formIds size:%{public}zu", formIds.size());
    return FormLifecycleAdapter::GetInstance().DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
}

int FormMgrAdapterFacade::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    return FormLifecycleAdapter::GetInstance().DeleteForm(formId, callerToken);
}

int FormMgrAdapterFacade::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken,
    const bool delCache)
{
    return FormLifecycleAdapter::GetInstance().ReleaseForm(formId, callerToken, delCache);
}

int FormMgrAdapterFacade::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("CastTempForm called, formId:%{public}" PRId64, formId);
    return FormLifecycleAdapter::GetInstance().CastTempForm(formId, callerToken);
}

int FormMgrAdapterFacade::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    return FormLifecycleAdapter::GetInstance().ReleaseRenderer(formId, compId);
}

int32_t FormMgrAdapterFacade::EnableForms(const std::string &bundleName, const int32_t userId, const bool enable)
{
    HILOG_INFO("EnableForms called, bundleName:%{public}s, userId:%{public}d, enable:%{public}d",
        bundleName.c_str(), userId, enable);
    return FormLifecycleAdapter::GetInstance().EnableForms(bundleName, userId, enable);
}

ErrCode FormMgrAdapterFacade::ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect)
{
    return FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, userId, protect);
}

ErrCode FormMgrAdapterFacade::SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock)
{
    return FormLifecycleAdapter::GetInstance().SwitchLockForms(bundleName, userId, lock);
}

int32_t FormMgrAdapterFacade::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    return FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
}

ErrCode FormMgrAdapterFacade::BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration)
{
    HILOG_INFO("BatchNotifyFormsConfigurationUpdate called");
    return FormLifecycleAdapter::GetInstance().BatchNotifyFormsConfigurationUpdate(configuration);
}

#ifdef RES_SCHEDULE_ENABLE
void FormMgrAdapterFacade::SetTimerTaskNeeded(bool isTimerTaskNeeded)
{
    FormLifecycleAdapter::GetInstance().SetTimerTaskNeeded(isTimerTaskNeeded);
}
#endif // RES_SCHEDULE_ENABLE

int FormMgrAdapterFacade::UpdateForm(const int64_t formId, const int32_t callingUid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    return FormDataAdapter::GetInstance().UpdateForm(formId, callingUid, formProviderData, formDataProxies);
}

int FormMgrAdapterFacade::RequestForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HILOG_INFO("RequestForm called, formId:%{public}" PRId64, formId);
    return FormDataAdapter::GetInstance().RequestForm(formId, callerToken, want);
}

ErrCode FormMgrAdapterFacade::UpdateFormSize(const int64_t &formId, float width, float height,
    float borderWidth, float formViewScale)
{
    HILOG_INFO("UpdateFormSize called, formId:%{public}" PRId64, formId);
    return FormDataAdapter::GetInstance().UpdateFormSize(formId, width, height, borderWidth, formViewScale);
}

ErrCode FormMgrAdapterFacade::UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
{
    return FormDataAdapter::GetInstance().UpdateFormSize(formId, newDimension, newRect);
}

ErrCode FormMgrAdapterFacade::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    return FormDataAdapter::GetInstance().UpdateFormLocation(formId, formLocation, isRequestPublishFormWithSnapshot);
}

int FormMgrAdapterFacade::EnableUpdateForm(const std::vector<int64_t> formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return FormDataAdapter::GetInstance().EnableUpdateForm(formIds, callerToken);
}

int FormMgrAdapterFacade::DisableUpdateForm(const std::vector<int64_t> formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return FormDataAdapter::GetInstance().DisableUpdateForm(formIds, callerToken);
}

ErrCode FormMgrAdapterFacade::BatchRefreshForms(const int32_t formRefreshType)
{
    return FormDataAdapter::GetInstance().BatchRefreshForms(formRefreshType);
}

int FormMgrAdapterFacade::NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    return FormVisibilityAdapter::GetInstance().NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
}

bool FormMgrAdapterFacade::HasFormVisible(const uint32_t tokenId)
{
    return FormVisibilityAdapter::GetInstance().HasFormVisible(tokenId);
}

int FormMgrAdapterFacade::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
    const sptr<IRemoteObject> &callerToken)
{
    return FormVisibilityAdapter::GetInstance().NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrAdapterFacade::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
    const sptr<IRemoteObject> &callerToken)
{
    return FormVisibilityAdapter::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
}

void FormMgrAdapterFacade::HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const std::unordered_map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    const std::unordered_map<std::string, std::vector<int64_t>> &eventMaps, const int32_t formVisibleType,
    const sptr<IRemoteObject> &callerToken)
{
    FormVisibilityAdapter::GetInstance().HandlerNotifyWhetherVisibleForms(formIds, formInstanceMaps,
        eventMaps, formVisibleType, callerToken);
}

void FormMgrAdapterFacade::PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
    std::unordered_map<std::string, std::vector<FormInstance>> &formInstanceMaps)
{
    HILOG_INFO("PaddingNotifyVisibleFormsMap called, formId:%{public}" PRId64, formId);
    FormVisibilityAdapter::GetInstance().PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
}

int32_t FormMgrAdapterFacade::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    return FormVisibilityAdapter::GetInstance().SetFormsRecyclable(formIds);
}

int32_t FormMgrAdapterFacade::RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
    bool isCheckCallingUid)
{
    HILOG_INFO("RecycleForms called, formIds size:%{public}zu", formIds.size());
    return FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, isCheckCallingUid);
}

int32_t FormMgrAdapterFacade::NotifyFormLocked(const int64_t &formId, bool isLocked)
{
    HILOG_INFO("NotifyFormLocked called, formId:%{public}" PRId64, formId);
    return FormVisibilityAdapter::GetInstance().NotifyFormLocked(formId, isLocked);
}

int FormMgrAdapterFacade::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetAllFormsInfo(formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByFilter(const FormInfoFilter &filter,
    std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetFormsInfoByFilter(filter, formInfos);
}

int FormMgrAdapterFacade::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetAllTemplateFormsInfo(formInfos);
}

int FormMgrAdapterFacade::GetTemplateFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetTemplateFormsInfoByApp(bundleName, formInfos);
}

int FormMgrAdapterFacade::GetTemplateFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    return FormQueryAdapter::GetInstance().GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos);
}

int32_t FormMgrAdapterFacade::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    return FormQueryAdapter::GetInstance().GetFormsCount(isTempFormFlag, formCount);
}

int32_t FormMgrAdapterFacade::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    return FormQueryAdapter::GetInstance().GetHostFormsCount(bundleName, formCount);
}

int FormMgrAdapterFacade::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
    FormStateInfo &stateInfo)
{
    HILOG_INFO("AcquireFormState called");
    return FormQueryAdapter::GetInstance().AcquireFormState(want, callerToken, stateInfo);
}

int FormMgrAdapterFacade::AcquireFormData(int64_t formId, int64_t requestCode,
    const sptr<IRemoteObject> &callerToken, AAFwk::WantParams &formData)
{
    HILOG_INFO("AcquireFormData called, formId:%{public}" PRId64 ", requestCode:%{public}" PRId64,
        formId, requestCode);
    return FormQueryAdapter::GetInstance().AcquireFormData(formId, requestCode, callerToken, formData);
}

ErrCode FormMgrAdapterFacade::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    return FormQueryAdapter::GetInstance().GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgrAdapterFacade::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
    FormInstance &formInstance)
{
    return FormQueryAdapter::GetInstance().GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfos(bool isUnusedIncluded,
    std::vector<RunningFormInfo> &runningFormInfos, const int32_t userId)
{
    return FormQueryAdapter::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos, userId);
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfosByBundleName(const std::string &bundleName,
    bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    return FormQueryAdapter::GetInstance().GetRunningFormInfosByBundleName(
        bundleName, isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrAdapterFacade::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    return FormQueryAdapter::GetInstance().GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgrAdapterFacade::RegisterFormAddObserverByBundle(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return FormObserverAdapter::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterFormRemoveObserverByBundle(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return FormObserverAdapter::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterAddObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return FormObserverAdapter::GetInstance().RegisterAddObserver(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterRemoveObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return FormObserverAdapter::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
}

void FormMgrAdapterFacade::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("CleanResource called");
    FormObserverAdapter::GetInstance().CleanResource(remote);
}

ErrCode FormMgrAdapterFacade::RegisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return FormObserverAdapter::GetInstance().RegisterClickEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgrAdapterFacade::UnregisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    return FormObserverAdapter::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, observer);
}

int FormMgrAdapterFacade::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    return FormDataAdapter::GetInstance().SetNextRefreshTime(formId, nextTime);
}

bool FormMgrAdapterFacade::GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const
{
    return FormCommonAdapter::GetInstance().GetValidFormUpdateDuration(formId, updateDuration);
}

void FormMgrAdapterFacade::UpdateFormCloudUpdateDuration(const std::string &bundleName)
{
    FormCommonAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);
}

bool FormMgrAdapterFacade::CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
{
    return FormCommonAdapter::GetInstance().CheckFormDueControl(formMajorInfo, isDisablePolicy);
}

ErrCode FormMgrAdapterFacade::HandleFormAddObserver(const int64_t formId)
{
    HILOG_INFO("HandleFormAddObserver called, formId:%{public}" PRId64, formId);
    return FormCommonAdapter::GetInstance().HandleFormAddObserver(formId);
}

ErrCode FormMgrAdapterFacade::HandleFormRemoveObserver(const RunningFormInfo runningFormInfo)
{
    HILOG_INFO("HandleFormRemoveObserver called");
    FormLifecycleAdapter::GetInstance().HandleFormRemoveObserver(runningFormInfo);
    return ERR_OK;
}

ErrCode FormMgrAdapterFacade::ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams)
{
    return FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
}

ErrCode FormMgrAdapterFacade::AcquireProviderFormInfoByFormRecord(const FormRecord &record,
    const WantParams &wantParams)
{
    HILOG_INFO("AcquireProviderFormInfoByFormRecord called");
    return FormDataAdapter::GetInstance().AcquireProviderFormInfoByFormRecord(record, wantParams);
}

void FormMgrAdapterFacade::ClearReconnectNum(int64_t formId)
{
    HILOG_INFO("ClearReconnectNum called, formId:%{public}" PRId64, formId);
    FormDataAdapter::GetInstance().ClearReconnectNum(formId);
}

ErrCode FormMgrAdapterFacade::ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms)
{
    return FormDataAdapter::GetInstance().ReloadForms(reloadNum, refreshForms);
}

bool FormMgrAdapterFacade::IsDeleteCacheInUpgradeScene(const FormRecord &record)
{
    return FormDataAdapter::GetInstance().IsDeleteCacheInUpgradeScene(record);
}

int32_t FormMgrAdapterFacade::OnNotifyRefreshForm(const int64_t &formId)
{
    return FormDataAdapter::GetInstance().OnNotifyRefreshForm(formId);
}

ErrCode FormMgrAdapterFacade::UpdateFormByCondition(int32_t type)
{
    return FormDataAdapter::GetInstance().UpdateFormByCondition(type);
}

void FormMgrAdapterFacade::DelayRefreshFormsOnAppUpgrade(const std::vector<FormRecord> &updatedForms, const Want &want)
{
    FormDataAdapter::GetInstance().DelayRefreshFormsOnAppUpgrade(updatedForms, want);
}

int FormMgrAdapterFacade::MessageEvent(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    return FormEventAdapter::GetInstance().MessageEvent(formId, want, callerToken);
}

int FormMgrAdapterFacade::RouterEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    return FormEventAdapter::GetInstance().RouterEvent(formId, want, callerToken);
}

int FormMgrAdapterFacade::BackgroundEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    return FormEventAdapter::GetInstance().BackgroundEvent(formId, want, callerToken);
}

void FormMgrAdapterFacade::SetFreeInstallFlag(const FormRecord &record, Want &want)
{
    HILOG_INFO("SetFreeInstallFlag called");
    FormEventAdapter::GetInstance().SetFreeInstallFlag(record, want);
}

bool FormMgrAdapterFacade::OpenByOpenType(const int32_t openType, const FormRecord &record,
    const sptr<IRemoteObject> &callerToken, Want &want, int32_t &openResult)
{
    HILOG_INFO("OpenByOpenType called, openType:%{public}d", openType);
    return FormEventAdapter::GetInstance().OpenByOpenType(openType, record, callerToken, want, openResult);
}

ErrCode FormMgrAdapterFacade::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    return FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
}

ErrCode FormMgrAdapterFacade::RegisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    return FormCallbackAdapter::GetInstance().RegisterPublishFormInterceptor(interceptorCallback);
}

ErrCode FormMgrAdapterFacade::UnregisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    return FormCallbackAdapter::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
}

ErrCode FormMgrAdapterFacade::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterOverflowProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterOverflowProxy()
{
    return FormCallbackAdapter::GetInstance().UnregisterOverflowProxy();
}

ErrCode FormMgrAdapterFacade::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    return FormCallbackAdapter::GetInstance().RequestOverflow(formId, callingUid, overflowInfo, isOverflow);
}

ErrCode FormMgrAdapterFacade::RegisterChangeSceneAnimationStateProxy(
    const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterChangeSceneAnimationStateProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterChangeSceneAnimationStateProxy()
{
    return FormCallbackAdapter::GetInstance().UnregisterChangeSceneAnimationStateProxy();
}

ErrCode FormMgrAdapterFacade::ChangeSceneAnimationState(const int64_t formId,
    const int32_t callingUid, int32_t state)
{
    return FormCallbackAdapter::GetInstance().ChangeSceneAnimationState(formId, callingUid, state);
}

ErrCode FormMgrAdapterFacade::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterGetFormRectProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterGetFormRectProxy()
{
    return FormCallbackAdapter::GetInstance().UnregisterGetFormRectProxy();
}

ErrCode FormMgrAdapterFacade::GetFormRect(const int64_t formId,
    const int32_t callingUid, Rect &rect)
{
    return FormCallbackAdapter::GetInstance().GetFormRect(formId, callingUid, rect);
}

ErrCode FormMgrAdapterFacade::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterGetLiveFormStatusProxy()
{
    return FormCallbackAdapter::GetInstance().UnregisterGetLiveFormStatusProxy();
}

ErrCode FormMgrAdapterFacade::GetLiveFormStatus(
    std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    return FormCallbackAdapter::GetInstance().GetLiveFormStatus(liveFormStatusMap);
}

ErrCode FormMgrAdapterFacade::RegisterPublishFormCrossBundleControl(
    const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterPublishFormCrossBundleControl(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterPublishFormCrossBundleControl()
{
    return FormCallbackAdapter::GetInstance().UnregisterPublishFormCrossBundleControl();
}

bool FormMgrAdapterFacade::PublishFormCrossBundleControl(
    const PublishFormCrossBundleInfo &bundleInfo)
{
    return FormCallbackAdapter::GetInstance().PublishFormCrossBundleControl(bundleInfo);
}

ErrCode FormMgrAdapterFacade::RegisterTemplateFormDetailInfoChange(
    const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterTemplateFormDetailInfoChange(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterTemplateFormDetailInfoChange()
{
    return FormCallbackAdapter::GetInstance().UnregisterTemplateFormDetailInfoChange();
}

ErrCode FormMgrAdapterFacade::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    return FormCallbackAdapter::GetInstance().UpdateTemplateFormDetailInfo(templateFormInfo);
}

ErrCode FormMgrAdapterFacade::RegisterUpdateFormsConfigCallback(const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterUpdateFormsConfigCallback(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterUpdateFormsConfigCallback()
{
    return FormCallbackAdapter::GetInstance().UnregisterUpdateFormsConfigCallback();
}

ErrCode FormMgrAdapterFacade::UpdateFormsConfig(const std::vector<FormCustomConfig> &configs)
{
    return FormCallbackAdapter::GetInstance().UpdateFormsConfig(configs);
}

ErrCode FormMgrAdapterFacade::RegisterDeleteFormsCallback(const sptr<IRemoteObject> &callerToken)
{
    return FormCallbackAdapter::GetInstance().RegisterDeleteFormsCallback(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterDeleteFormsCallback()
{
    return FormCallbackAdapter::GetInstance().UnregisterDeleteFormsCallback();
}

ErrCode FormMgrAdapterFacade::DeleteForms(const std::vector<FormRecordFilter> &filters)
{
    return FormCallbackAdapter::GetInstance().DeleteForms(filters);
}

ErrCode FormMgrAdapterFacade::StartAbilityByFms(const Want &want)
{
    HILOG_INFO("StartAbilityByFms called");
    return FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
}

int FormMgrAdapterFacade::DumpStorageFormInfos(std::string &formInfos) const
{
    HILOG_INFO("DumpStorageFormInfos called");
    return FormDebugAdapter::GetInstance().DumpStorageFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpTemporaryFormInfos(std::string &formInfos) const
{
    return FormDebugAdapter::GetInstance().DumpTemporaryFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpStaticBundleFormInfos(std::string &formInfos) const
{
    return FormDebugAdapter::GetInstance().DumpStaticBundleFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpFormInfoByBundleName(const std::string &bundleName,
    std::string &formInfos) const
{
    return FormDebugAdapter::GetInstance().DumpFormInfoByBundleName(bundleName, formInfos);
}

int FormMgrAdapterFacade::DumpFormInfoByFormId(const int64_t formId,
    std::string &formInfo) const
{
    return FormDebugAdapter::GetInstance().DumpFormInfoByFormId(formId, formInfo);
}

int FormMgrAdapterFacade::DumpFormTimerByFormId(const int64_t formId,
    std::string &isTimingService) const
{
    return FormDebugAdapter::GetInstance().DumpFormTimerByFormId(formId, isTimingService);
}

int FormMgrAdapterFacade::DumpHasFormVisible(const std::string &bundleInfo,
    std::string &formInfos) const
{
    return FormDebugAdapter::GetInstance().DumpHasFormVisible(bundleInfo, formInfos);
}

int FormMgrAdapterFacade::DumpFormRunningFormInfos(std::string &runningFormInfosResult) const
{
    return FormDebugAdapter::GetInstance().DumpFormRunningFormInfos(runningFormInfosResult);
}

ErrCode FormMgrAdapterFacade::RegisterFormWantCallback(int32_t callingUid,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("RegisterFormWantCallback called");
    return FormCallbackAdapter::GetInstance().RegisterFormWantCallback(callingUid, callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterFormWantCallback(int32_t callingUid)
{
    HILOG_INFO("UnregisterFormWantCallback called");
    return FormCallbackAdapter::GetInstance().UnregisterFormWantCallback(callingUid);
}

ErrCode FormMgrAdapterFacade::GetWantCallbackProxy(int32_t callingUid, sptr<IRemoteObject> &proxy)
{
    return FormCallbackAdapter::GetInstance().GetWantCallbackProxy(callingUid, proxy);
}
} // namespace AppExecFwk
} // namespace OHOS
