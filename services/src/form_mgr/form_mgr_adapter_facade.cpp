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
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

FormMgrAdapterFacade::FormMgrAdapterFacade(
    FormLifecycleAdapter* lifecycleAdapter,
    FormDataAdapter* dataAdapter,
    FormVisibilityAdapter* visibilityAdapter,
    FormQueryAdapter* queryAdapter,
    FormEventAdapter* eventAdapter,
    FormObserverAdapter* observerAdapter,
    FormPublishAdapter* publishAdapter,
    FormCallbackAdapter* callbackAdapter,
    FormDebugAdapter* debugAdapter,
    FormCommonAdapter* commonAdapter)
    : lifecycleAdapter_(lifecycleAdapter),
      dataAdapter_(dataAdapter),
      visibilityAdapter_(visibilityAdapter),
      queryAdapter_(queryAdapter),
      eventAdapter_(eventAdapter),
      observerAdapter_(observerAdapter),
      publishAdapter_(publishAdapter),
      callbackAdapter_(callbackAdapter),
      debugAdapter_(debugAdapter),
      commonAdapter_(commonAdapter)
{
    HILOG_INFO("FormMgrAdapterFacade created with all adapters");
}

void FormMgrAdapterFacade::Init()
{
    HILOG_INFO("FormMgrAdapterFacade::Init called");
    // Note: Individual adapters handle their own initialization internally.
    // This method is provided for API compatibility with FormMgrAdapter.

    // Clean up invalid form cache (only executes once)
    dataAdapter_->DeleteInvalidFormCacheIfNeed();
}

ErrCode FormMgrAdapterFacade::QueryPublishFormToHost(Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::QueryPublishFormToHost called");
    return publishAdapter_->QueryPublishFormToHost(want);
}

ErrCode FormMgrAdapterFacade::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    HILOG_INFO("FormMgrAdapterFacade::RequestPublishForm called");
    return publishAdapter_->RequestPublishForm(want, withFormBindingData, formBindingData, formId,
        formDataProxies, needCheckFormPermission);
}

ErrCode FormMgrAdapterFacade::SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::SetPublishFormResult called, formId:%{public}" PRId64, formId);
    return publishAdapter_->SetPublishFormResult(formId, errorCodeInfo);
}

ErrCode FormMgrAdapterFacade::AcquireAddFormResult(const int64_t formId)
{
    HILOG_INFO("FormMgrAdapterFacade::AcquireAddFormResult called, formId:%{public}" PRId64, formId);
    return publishAdapter_->AcquireAddFormResult(formId);
}

bool FormMgrAdapterFacade::IsRequestPublishFormSupported()
{
    HILOG_INFO("FormMgrAdapterFacade::IsRequestPublishFormSupported called");
    return publishAdapter_->IsRequestPublishFormSupported();
}

int FormMgrAdapterFacade::AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::AddForm called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->AddForm(formId, want, callerToken, formInfo);
}

int FormMgrAdapterFacade::CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::CreateForm called");
    return lifecycleAdapter_->CreateForm(want, runningFormInfo);
}

int FormMgrAdapterFacade::StopRenderingForm(const int64_t formId, const std::string &compId)
{
    HILOG_INFO("FormMgrAdapterFacade::StopRenderingForm called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->StopRenderingForm(formId, compId);
}

int FormMgrAdapterFacade::DeleteInvalidForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted)
{
    HILOG_INFO("FormMgrAdapterFacade::DeleteInvalidForms called, formIds size:%{public}zu", formIds.size());
    return lifecycleAdapter_->DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
}

int FormMgrAdapterFacade::DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::DeleteForm called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->DeleteForm(formId, callerToken);
}

int FormMgrAdapterFacade::ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken,
    const bool delCache)
{
    HILOG_INFO("FormMgrAdapterFacade::ReleaseForm called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->ReleaseForm(formId, callerToken, delCache);
}

int FormMgrAdapterFacade::CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::CastTempForm called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->CastTempForm(formId, callerToken);
}

int FormMgrAdapterFacade::ReleaseRenderer(int64_t formId, const std::string &compId)
{
    HILOG_INFO("FormMgrAdapterFacade::ReleaseRenderer called, formId:%{public}" PRId64, formId);
    return lifecycleAdapter_->ReleaseRenderer(formId, compId);
}

int32_t FormMgrAdapterFacade::EnableForms(const std::string bundleName, const int32_t userId, const bool enable)
{
    HILOG_INFO("FormMgrAdapterFacade::EnableForms called, bundleName:%{public}s, userId:%{public}d, enable:%{public}d",
        bundleName.c_str(), userId, enable);
    return lifecycleAdapter_->EnableForms(bundleName, userId, enable);
}

ErrCode FormMgrAdapterFacade::ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect)
{
    HILOG_INFO("FormMgrAdapterFacade::ProtectLockForms called, bundleName:%{public}s, userId:%{public}d,
        protect:%{public}d", bundleName.c_str(), userId, protect);
    return lifecycleAdapter_->ProtectLockForms(bundleName, userId, protect);
}

ErrCode FormMgrAdapterFacade::SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock)
{
    HILOG_INFO("FormMgrAdapterFacade::SwitchLockForms called, bundleName:%{public}s, userId:%{public}d,
        lock:%{public}d", bundleName.c_str(), userId, lock);
    return lifecycleAdapter_->SwitchLockForms(bundleName, userId, lock);
}

int32_t FormMgrAdapterFacade::RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::RecoverForms called, formIds size:%{public}zu", formIds.size());
    return lifecycleAdapter_->RecoverForms(formIds, want);
}

ErrCode FormMgrAdapterFacade::BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration)
{
    HILOG_INFO("FormMgrAdapterFacade::BatchNotifyFormsConfigurationUpdate called");
    return lifecycleAdapter_->BatchNotifyFormsConfigurationUpdate(configuration);
}

#ifdef RES_SCHEDULE_ENABLE
void FormMgrAdapterFacade::SetTimerTaskNeeded(bool isTimerTaskNeeded)
{
    HILOG_INFO("FormMgrAdapterFacade::SetTimerTaskNeeded called, isTimerTaskNeeded:%{public}d", isTimerTaskNeeded);
    lifecycleAdapter_->SetTimerTaskNeeded(isTimerTaskNeeded);
}
#endif // RES_SCHEDULE_ENABLE

int FormMgrAdapterFacade::UpdateForm(const int64_t formId, const int32_t callingUid,
    const FormProviderData &formProviderData, const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateForm called, formId:%{public}" PRId64, formId);
    return dataAdapter_->UpdateForm(formId, callingUid, formProviderData, formDataProxies);
}

int FormMgrAdapterFacade::RequestForm(const int64_t formId,
    const sptr<IRemoteObject> &callerToken, const Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::RequestForm called, formId:%{public}" PRId64, formId);
    return dataAdapter_->RequestForm(formId, callerToken, want);
}

ErrCode FormMgrAdapterFacade::UpdateFormSize(const int64_t &formId, float width, float height,
    float borderWidth, float formViewScale)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateFormSize called, formId:%{public}" PRId64, formId);
    return dataAdapter_->UpdateFormSize(formId, width, height, borderWidth, formViewScale);
}

ErrCode FormMgrAdapterFacade::UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateFormSize(dimension) called, formId:%{public}" PRId64 ",
        dimension:%{public}d", formId, newDimension);
    return dataAdapter_->UpdateFormSize(formId, newDimension, newRect);
}

ErrCode FormMgrAdapterFacade::UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
    const bool isRequestPublishFormWithSnapshot)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateFormLocation called, formId:%{public}" PRId64, formId);
    return dataAdapter_->UpdateFormLocation(formId, formLocation, isRequestPublishFormWithSnapshot);
}

int FormMgrAdapterFacade::EnableUpdateForm(const std::vector<int64_t> formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::EnableUpdateForm called, formIds size:%{public}zu", formIds.size());
    return dataAdapter_->EnableUpdateForm(formIds, callerToken);
}

int FormMgrAdapterFacade::DisableUpdateForm(const std::vector<int64_t> formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::DisableUpdateForm called, formIds size:%{public}zu", formIds.size());
    return dataAdapter_->DisableUpdateForm(formIds, callerToken);
}

ErrCode FormMgrAdapterFacade::BatchRefreshForms(const int32_t formRefreshType)
{
    HILOG_INFO("FormMgrAdapterFacade::BatchRefreshForms called, type:%{public}d", formRefreshType);
    std::vector<int64_t> formIds;
    return dataAdapter_->BatchRefreshForms(formIds);
}

int FormMgrAdapterFacade::NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    HILOG_INFO("FormMgrAdapterFacade::NotifyWhetherVisibleForms called, formIds size:%{public}zu", formIds.size());
    return visibilityAdapter_->NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType);
}

bool FormMgrAdapterFacade::HasFormVisible(const uint32_t tokenId)
{
    HILOG_INFO("FormMgrAdapterFacade::HasFormVisible called, tokenId:%{public}u", tokenId);
    return visibilityAdapter_->HasFormVisible(tokenId);
}

int FormMgrAdapterFacade::NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::NotifyFormsVisible called, formIds size:%{public}zu", formIds.size());
    return visibilityAdapter_->NotifyFormsVisible(formIds, isVisible, callerToken);
}

int FormMgrAdapterFacade::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::NotifyFormsEnableUpdate called, formIds size:%{public}zu", formIds.size());
    return visibilityAdapter_->NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken);
}

void FormMgrAdapterFacade::HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::HandlerNotifyWhetherVisibleForms called,
        formIds size:%{public}zu", formIds.size());
    visibilityAdapter_->HandlerNotifyWhetherVisibleForms(formIds, formInstanceMaps, eventMaps, formVisibleType,
        callerToken);
}

void FormMgrAdapterFacade::PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps)
{
    HILOG_INFO("FormMgrAdapterFacade::PaddingNotifyVisibleFormsMap called, formId:%{public}" PRId64, formId);
    visibilityAdapter_->PaddingNotifyVisibleFormsMap(formVisibleType, formId, formInstanceMaps);
}

int32_t FormMgrAdapterFacade::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_INFO("FormMgrAdapterFacade::SetFormsRecyclable called, formIds size:%{public}zu", formIds.size());
    return visibilityAdapter_->SetFormsRecyclable(formIds);
}

int32_t FormMgrAdapterFacade::RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
    bool isCheckCallingUid)
{
    HILOG_INFO("FormMgrAdapterFacade::RecycleForms called, formIds size:%{public}zu", formIds.size());
    return visibilityAdapter_->RecycleForms(formIds, want, isCheckCallingUid);
}

int32_t FormMgrAdapterFacade::NotifyFormLocked(const int64_t &formId, bool isLocked)
{
    HILOG_INFO("FormMgrAdapterFacade::NotifyFormLocked called, formId:%{public}" PRId64, formId);
    return visibilityAdapter_->NotifyFormLocked(formId, isLocked);
}

int FormMgrAdapterFacade::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetAllFormsInfo called");
    return queryAdapter_->GetAllFormsInfo(formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormsInfoByApp called, bundleName:%{public}s", bundleName.c_str());
    return queryAdapter_->GetFormsInfoByApp(bundleName, formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormsInfoByModule called, bundleName:%{public}s, moduleName:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    return queryAdapter_->GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

int FormMgrAdapterFacade::GetFormsInfoByFilter(const FormInfoFilter &filter,
    std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormsInfoByFilter called");
    return queryAdapter_->GetFormsInfoByFilter(filter, formInfos);
}

int FormMgrAdapterFacade::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetAllTemplateFormsInfo called");
    return queryAdapter_->GetAllTemplateFormsInfo(formInfos);
}

int FormMgrAdapterFacade::GetTemplateFormsInfoByApp(const std::string &bundleName,
    std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetTemplateFormsInfoByApp called, bundleName:%{public}s", bundleName.c_str());
    return queryAdapter_->GetTemplateFormsInfoByApp(bundleName, formInfos);
}

int FormMgrAdapterFacade::GetTemplateFormsInfoByModule(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetTemplateFormsInfoByModule called, bundleName:%{public}s,
        moduleName:%{public}s", bundleName.c_str(), moduleName.c_str());
    return queryAdapter_->GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos);
}

int32_t FormMgrAdapterFacade::GetFormsCount(bool isTempFormFlag, int32_t &formCount)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormsCount called, isTempFormFlag:%{public}d", isTempFormFlag);
    return queryAdapter_->GetFormsCount(isTempFormFlag, formCount);
}

int32_t FormMgrAdapterFacade::GetHostFormsCount(std::string &bundleName, int32_t &formCount)
{
    HILOG_INFO("FormMgrAdapterFacade::GetHostFormsCount called, bundleName:%{public}s", bundleName.c_str());
    return queryAdapter_->GetHostFormsCount(bundleName, formCount);
}

int FormMgrAdapterFacade::AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
    FormStateInfo &stateInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::AcquireFormState called");
    return queryAdapter_->AcquireFormState(want, callerToken, stateInfo);
}

int FormMgrAdapterFacade::AcquireFormData(int64_t formId, int64_t requestCode,
    const sptr<IRemoteObject> &callerToken, AAFwk::WantParams &formData)
{
    HILOG_INFO("FormMgrAdapterFacade::AcquireFormData called, formId:%{public}" PRId64 ", requestCode:%{public}" PRId64,
        formId, requestCode);
    return queryAdapter_->AcquireFormData(formId, requestCode, callerToken, formData);
}

ErrCode FormMgrAdapterFacade::GetFormInstanceById(const int64_t formId, FormInstance &formInstance)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormInstanceById called, formId:%{public}" PRId64, formId);
    return queryAdapter_->GetFormInstanceById(formId, formInstance);
}

ErrCode FormMgrAdapterFacade::GetFormInstanceById(const int64_t formId, bool isUnusedIncluded,
    FormInstance &formInstance)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormInstanceById called, formId:%{public}" PRId64, formId);
    return queryAdapter_->GetFormInstanceById(formId, isUnusedIncluded, formInstance);
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfos(bool isUnusedIncluded,
    std::vector<RunningFormInfo> &runningFormInfos, const int32_t userId)
{
    HILOG_INFO("FormMgrAdapterFacade::GetRunningFormInfos called, userId:%{public}d", userId);
    return queryAdapter_->GetRunningFormInfos(isUnusedIncluded, runningFormInfos, userId);
}

ErrCode FormMgrAdapterFacade::GetRunningFormInfosByBundleName(const std::string &bundleName,
    bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos)
{
    HILOG_INFO("FormMgrAdapterFacade::GetRunningFormInfosByBundleName called, bundleName:%{public}s",
        bundleName.c_str());
    return queryAdapter_->GetRunningFormInfosByBundleName(bundleName, isUnusedIncluded, runningFormInfos);
}

ErrCode FormMgrAdapterFacade::GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
    std::vector<FormInstance> &formInstances)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormInstancesByFilter called");
    return queryAdapter_->GetFormInstancesByFilter(formInstancesFilter, formInstances);
}

ErrCode FormMgrAdapterFacade::RegisterFormAddObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterFormAddObserverByBundle called, bundleName:%{public}s",
        bundleName.c_str());
    return observerAdapter_->RegisterFormAddObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterFormRemoveObserverByBundle(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterFormRemoveObserverByBundle called, bundleName:%{public}s",
        bundleName.c_str());
    return observerAdapter_->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterAddObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterAddObserver called, bundleName:%{public}s", bundleName.c_str());
    return observerAdapter_->RegisterAddObserver(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::RegisterRemoveObserver(const std::string &bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterRemoveObserver called, bundleName:%{public}s", bundleName.c_str());
    return observerAdapter_->RegisterRemoveObserver(bundleName, callerToken);
}

ErrCode FormMgrAdapterFacade::HandleFormAddObserver(const int64_t formId)
{
    HILOG_INFO("FormMgrAdapterFacade::HandleFormAddObserver called, formId:%{public}" PRId64, formId);
    return observerAdapter_->HandleFormAddObserver(formId);
}

ErrCode FormMgrAdapterFacade::HandleFormRemoveObserver(const RunningFormInfo runningFormInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::HandleFormRemoveObserver called");
    return observerAdapter_->HandleFormRemoveObserver(runningFormInfo);
}

void FormMgrAdapterFacade::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("FormMgrAdapterFacade::CleanResource called");
    observerAdapter_->CleanResource(remote);
}

ErrCode FormMgrAdapterFacade::RegisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterClickEventObserver called, bundleName:%{public}s,
        formEventType:%{public}s", bundleName.c_str(), formEventType.c_str());
    return observerAdapter_->RegisterClickEventObserver(bundleName, formEventType, observer);
}

ErrCode FormMgrAdapterFacade::UnregisterClickEventObserver(const std::string &bundleName,
    const std::string &formEventType, const sptr<IRemoteObject> &observer)
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterClickEventObserver called, bundleName:%{public}s,
        formEventType:%{public}s", bundleName.c_str(), formEventType.c_str());
    return observerAdapter_->UnregisterClickEventObserver(bundleName, formEventType, observer);
}

int FormMgrAdapterFacade::SetNextRefreshTime(const int64_t formId, const int64_t nextTime)
{
    HILOG_INFO("FormMgrAdapterFacade::SetNextRefreshTime called, formId:%{public}" PRId64 ", nextTime:%{public}" PRId64,
        formId, nextTime);
    return dataAdapter_->SetNextRefreshTime(formId, nextTime);
}

bool FormMgrAdapterFacade::GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const
{
    HILOG_INFO("FormMgrAdapterFacade::GetValidFormUpdateDuration called, formId:%{public}" PRId64, formId);
    return commonAdapter_->GetValidFormUpdateDuration(formId, updateDuration);
}

void FormMgrAdapterFacade::UpdateFormCloudUpdateDuration(const std::string &bundleName)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateFormCloudUpdateDuration called, bundleName:%{public}s", bundleName.c_str());
    commonAdapter_->UpdateFormCloudUpdateDuration(bundleName);
}

ErrCode FormMgrAdapterFacade::ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams)
{
    HILOG_INFO("FormMgrAdapterFacade::ReAcquireProviderFormInfoAsync called");
    return dataAdapter_->ReAcquireProviderFormInfoAsync(info, wantParams);
}

ErrCode FormMgrAdapterFacade::AcquireProviderFormInfoByFormRecord(const FormRecord &record,
    const WantParams &wantParams)
{
    HILOG_INFO("FormMgrAdapterFacade::AcquireProviderFormInfoByFormRecord called");
    return dataAdapter_->AcquireProviderFormInfoByFormRecord(record, wantParams);
}

void FormMgrAdapterFacade::ClearReconnectNum(int64_t formId)
{
    HILOG_INFO("FormMgrAdapterFacade::ClearReconnectNum called, formId:%{public}" PRId64, formId);
    dataAdapter_->ClearReconnectNum(formId);
}

ErrCode FormMgrAdapterFacade::ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms)
{
    HILOG_INFO("FormMgrAdapterFacade::ReloadForms called, refreshForms size:%{public}zu", refreshForms.size());
    return dataAdapter_->ReloadForms(reloadNum, refreshForms);
}

bool FormMgrAdapterFacade::CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
{
    HILOG_INFO("FormMgrAdapterFacade::CheckFormDueControl called");
    return commonAdapter_->CheckFormDueControl(formMajorInfo, isDisablePolicy);
}

bool FormMgrAdapterFacade::IsDeleteCacheInUpgradeScene(const FormRecord &record)
{
    HILOG_INFO("FormMgrAdapterFacade::IsDeleteCacheInUpgradeScene called");
    return dataAdapter_->IsDeleteCacheInUpgradeScene(record);
}

int32_t FormMgrAdapterFacade::OnNotifyRefreshForm(const int64_t &formId)
{
    HILOG_INFO("FormMgrAdapterFacade::OnNotifyRefreshForm called, formId:%{public}" PRId64, formId);
    return dataAdapter_->OnNotifyRefreshForm(formId);
}

ErrCode FormMgrAdapterFacade::UpdateFormByCondition(int32_t type)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateFormByCondition called, type:%{public}d", type);
    return dataAdapter_->UpdateFormByCondition(type);
}

void FormMgrAdapterFacade::DelayRefreshFormsOnAppUpgrade(const std::vector<FormRecord> &updatedForms, const Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::DelayRefreshFormsOnAppUpgrade called, updatedForms size:%{public}zu",
        updatedForms.size());
    dataAdapter_->DelayRefreshFormsOnAppUpgrade(updatedForms, want);
}

int FormMgrAdapterFacade::MessageEvent(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::MessageEvent called, formId:%{public}" PRId64, formId);
    return eventAdapter_->MessageEvent(formId, want, callerToken);
}

int FormMgrAdapterFacade::RouterEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RouterEvent called, formId:%{public}" PRId64, formId);
    return eventAdapter_->RouterEvent(formId, want, callerToken);
}

int FormMgrAdapterFacade::BackgroundEvent(const int64_t formId, Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::BackgroundEvent called, formId:%{public}" PRId64, formId);
    return eventAdapter_->BackgroundEvent(formId, want, callerToken);
}

void FormMgrAdapterFacade::SetFreeInstallFlag(const FormRecord &record, Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::SetFreeInstallFlag called");
    eventAdapter_->SetFreeInstallFlag(record, want);
}

bool FormMgrAdapterFacade::OpenByOpenType(const int32_t openType, const FormRecord &record,
    const sptr<IRemoteObject> &callerToken, Want &want, int32_t &openResult)
{
    HILOG_INFO("FormMgrAdapterFacade::OpenByOpenType called, openType:%{public}d", openType);
    return eventAdapter_->OpenByOpenType(openType, record, callerToken, want, openResult);
}

ErrCode FormMgrAdapterFacade::RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterFormRouterProxy called, formIds size:%{public}zu", formIds.size());
    return callbackAdapter_->RegisterFormRouterProxy(formIds, callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterFormRouterProxy called, formIds size:%{public}zu", formIds.size());
    return callbackAdapter_->UnregisterFormRouterProxy(formIds);
}

ErrCode FormMgrAdapterFacade::RegisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterPublishFormInterceptor called");
    return callbackAdapter_->RegisterPublishFormInterceptor(interceptorCallback);
}

ErrCode FormMgrAdapterFacade::UnregisterPublishFormInterceptor(
    const sptr<IRemoteObject> &interceptorCallback)
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterPublishFormInterceptor called");
    return callbackAdapter_->UnregisterPublishFormInterceptor(interceptorCallback);
}

ErrCode FormMgrAdapterFacade::RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterOverflowProxy called");
    return callbackAdapter_->RegisterOverflowProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterOverflowProxy()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterOverflowProxy called");
    return callbackAdapter_->UnregisterOverflowProxy();
}

ErrCode FormMgrAdapterFacade::RequestOverflow(const int64_t formId, const int32_t callingUid,
    const OverflowInfo &overflowInfo, bool isOverflow)
{
    HILOG_INFO("FormMgrAdapterFacade::RequestOverflow called, formId:%{public}" PRId64, formId);
    return callbackAdapter_->RequestOverflow(formId, callingUid, overflowInfo, isOverflow);
}

ErrCode FormMgrAdapterFacade::RegisterChangeSceneAnimationStateProxy(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterChangeSceneAnimationStateProxy called");
    return callbackAdapter_->RegisterChangeSceneAnimationStateProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterChangeSceneAnimationStateProxy()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterChangeSceneAnimationStateProxy called");
    return callbackAdapter_->UnregisterChangeSceneAnimationStateProxy();
}

ErrCode FormMgrAdapterFacade::ChangeSceneAnimationState(const int64_t formId,
    const int32_t callingUid, int32_t state)
{
    HILOG_INFO("FormMgrAdapterFacade::ChangeSceneAnimationState called, formId:%{public}" PRId64, formId);
    return callbackAdapter_->ChangeSceneAnimationState(formId, callingUid, state);
}

ErrCode FormMgrAdapterFacade::RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterGetFormRectProxy called");
    return callbackAdapter_->RegisterGetFormRectProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterGetFormRectProxy()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterGetFormRectProxy called");
    return callbackAdapter_->UnregisterGetFormRectProxy();
}

ErrCode FormMgrAdapterFacade::GetFormRect(const int64_t formId,
    const int32_t callingUid, Rect &rect)
{
    HILOG_INFO("FormMgrAdapterFacade::GetFormRect called, formId:%{public}" PRId64, formId);
    return callbackAdapter_->GetFormRect(formId, callingUid, rect);
}

ErrCode FormMgrAdapterFacade::RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterGetLiveFormStatusProxy called");
    return callbackAdapter_->RegisterGetLiveFormStatusProxy(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterGetLiveFormStatusProxy()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterGetLiveFormStatusProxy called");
    return callbackAdapter_->UnregisterGetLiveFormStatusProxy();
}

ErrCode FormMgrAdapterFacade::GetLiveFormStatus(
    std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    HILOG_INFO("FormMgrAdapterFacade::GetLiveFormStatus called");
    return callbackAdapter_->GetLiveFormStatus(liveFormStatusMap);
}

ErrCode FormMgrAdapterFacade::RegisterPublishFormCrossBundleControl(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterPublishFormCrossBundleControl called");
    return callbackAdapter_->RegisterPublishFormCrossBundleControl(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterPublishFormCrossBundleControl()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterPublishFormCrossBundleControl called");
    return callbackAdapter_->UnregisterPublishFormCrossBundleControl();
}

bool FormMgrAdapterFacade::PublishFormCrossBundleControl(
    const PublishFormCrossBundleInfo &bundleInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::PublishFormCrossBundleControl called");
    return callbackAdapter_->PublishFormCrossBundleControl(bundleInfo);
}

ErrCode FormMgrAdapterFacade::RegisterTemplateFormDetailInfoChange(
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("FormMgrAdapterFacade::RegisterTemplateFormDetailInfoChange called");
    return callbackAdapter_->RegisterTemplateFormDetailInfoChange(callerToken);
}

ErrCode FormMgrAdapterFacade::UnregisterTemplateFormDetailInfoChange()
{
    HILOG_INFO("FormMgrAdapterFacade::UnregisterTemplateFormDetailInfoChange called");
    return callbackAdapter_->UnregisterTemplateFormDetailInfoChange();
}

ErrCode FormMgrAdapterFacade::UpdateTemplateFormDetailInfo(
    const std::vector<TemplateFormDetailInfo> &templateFormInfo)
{
    HILOG_INFO("FormMgrAdapterFacade::UpdateTemplateFormDetailInfo called");
    return callbackAdapter_->UpdateTemplateFormDetailInfo(templateFormInfo);
}

ErrCode FormMgrAdapterFacade::StartAbilityByFms(const Want &want)
{
    HILOG_INFO("FormMgrAdapterFacade::StartAbilityByFms called");
    return callbackAdapter_->StartAbilityByFms(want);
}

int FormMgrAdapterFacade::DumpStorageFormInfos(std::string &formInfos) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpStorageFormInfos called");
    return debugAdapter_->DumpStorageFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpTemporaryFormInfos(std::string &formInfos) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpTemporaryFormInfos called");
    return debugAdapter_->DumpTemporaryFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpStaticBundleFormInfos(std::string &formInfos) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpStaticBundleFormInfos called");
    return debugAdapter_->DumpStaticBundleFormInfos(formInfos);
}

int FormMgrAdapterFacade::DumpFormInfoByBundleName(const std::string &bundleName,
    std::string &formInfos) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpFormInfoByBundleName called");
    return debugAdapter_->DumpFormInfoByBundleName(bundleName, formInfos);
}

int FormMgrAdapterFacade::DumpFormInfoByFormId(const int64_t formId,
    std::string &formInfo) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpFormInfoByFormId called");
    return debugAdapter_->DumpFormInfoByFormId(formId, formInfo);
}

int FormMgrAdapterFacade::DumpFormTimerByFormId(const int64_t formId,
    std::string &isTimingService) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpFormTimerByFormId called");
    return debugAdapter_->DumpFormTimerByFormId(formId, isTimingService);
}

int FormMgrAdapterFacade::DumpHasFormVisible(const std::string &bundleInfo,
    std::string &formInfos) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpHasFormVisible called");
    return debugAdapter_->DumpHasFormVisible(bundleInfo, formInfos);
}

int FormMgrAdapterFacade::DumpFormRunningFormInfos(std::string &runningFormInfosResult) const
{
    HILOG_INFO("FormMgrAdapterFacade::DumpFormRunningFormInfos called");
    return debugAdapter_->DumpFormRunningFormInfos(runningFormInfosResult);
}
} // namespace AppExecFwk
} // namespace OHOS
