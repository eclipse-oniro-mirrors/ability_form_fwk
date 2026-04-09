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

#ifndef OHOS_FORM_FWK_FORM_MGR_ADAPTER_FACADE_H
#define OHOS_FORM_FWK_FORM_MGR_ADAPTER_FACADE_H

#include "configuration.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_js_info.h"
#include "form_mgr_errors.h"
#include "form_provider_data.h"
#include "form_state_info.h"
#include "form_mgr_interface.h"
#include "running_form_info.h"
#include "template_form_detail_info.h"

#include "fms_log_wrapper.h"
#include "form_mgr/form_callback_adapter.h"
#include "form_mgr/form_common_adapter.h"
#include "form_mgr/form_data_adapter.h"
#include "form_mgr/form_debug_adapter.h"
#include "form_mgr/form_event_adapter.h"
#include "form_mgr/form_lifecycle_adapter.h"
#include "form_mgr/form_observer_adapter.h"
#include "form_mgr/form_publish_adapter.h"
#include "form_mgr/form_query_adapter.h"
#include "form_mgr/form_visibility_adapter.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormMgrAdapterFacade
 * 
 * Facade class that delegates all form management operations to specialized adapters.
 * This class follows the Facade pattern to provide a unified interface while
 * delegating to specialized adapters for different concerns.
 *
 * Design Note: This class does NOT inherit from IFormMgr. It is a standalone facade
 * that provides the same public interface as FormMgrAdapter for backward compatibility.
 */
class FormMgrAdapterFacade {
public:
    /**
     * @brief Constructor
     * @param lifecycleAdapter Lifecycle management adapter
     * @param dataAdapter Data update management adapter
     * @param visibilityAdapter Visibility management adapter
     * @param queryAdapter Query management adapter
     * @param eventAdapter Event handling adapter
     * @param observerAdapter Observer management adapter
     * @param publishAdapter Publish management adapter
     * @param callbackAdapter Callback management adapter
     * @param debugAdapter Debug/dump adapter
     * @param commonAdapter Shared common adapter instance
     */
    FormMgrAdapterFacade(
        FormLifecycleAdapter* lifecycleAdapter,
        FormDataAdapter* dataAdapter,
        FormVisibilityAdapter* visibilityAdapter,
        FormQueryAdapter* queryAdapter,
        FormEventAdapter* eventAdapter,
        FormObserverAdapter* observerAdapter,
        FormPublishAdapter* publishAdapter,
        FormCallbackAdapter* callbackAdapter,
        FormDebugAdapter* debugAdapter,
        FormCommonAdapter* commonAdapter);

    virtual ~FormMgrAdapterFacade() = default;

    /**
     * @brief Initialize the facade.
     *
     * Note: Individual adapters handle their own initialization internally.
     * This method is provided for API compatibility with FormMgrAdapter.
     */
    void Init();

    // ==================== Lifecycle Management ====================

    int AddForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo);

    int CreateForm(const Want &want, RunningFormInfo &runningFormInfo);

    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    int StopRenderingForm(const int64_t formId, const std::string &compId);

    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache);

    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    int DeleteInvalidForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, int32_t &numFormsDeleted);

    int ReleaseRenderer(int64_t formId, const std::string &compId);

    int32_t EnableForms(const std::string bundleName, const int32_t userId, const bool enable);

    ErrCode ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect);

    ErrCode SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock);

    int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want);

    ErrCode BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration);

#ifdef RES_SCHEDULE_ENABLE
    /**
     * @brief Set the value which indicate whether Refresh Timer task should be triggered.
     * @param isTimerTaskNeeded The value of whether Refresh Timer task should be triggered.
     */
    void SetTimerTaskNeeded(bool isTimerTaskNeeded);
#endif // RES_SCHEDULE_ENABLE

    // ==================== Data Update Management ====================

    int UpdateForm(const int64_t formId, const int32_t callingUid,
        const FormProviderData &formProviderData,
        const std::vector<FormDataProxy> &formDataProxies = {});

    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want);

    ErrCode UpdateFormSize(const int64_t &formId, float width, float height,
        float borderWidth, float formViewScale);

    ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect);

    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
        const bool isRequestPublishFormWithSnapshot = false);

    int EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken);

    int DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken);

    ErrCode BatchRefreshForms(const int32_t formRefreshType);

    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime);

    bool GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const;

    void UpdateFormCloudUpdateDuration(const std::string &bundleName);

    ErrCode ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams);

    ErrCode AcquireProviderFormInfoByFormRecord(const FormRecord &record, const WantParams &wantParams);

    void ClearReconnectNum(int64_t formId);

    ErrCode ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms);

    bool CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy);

    bool IsDeleteCacheInUpgradeScene(const FormRecord &record);

    int32_t OnNotifyRefreshForm(const int64_t &formId);

    ErrCode UpdateFormByCondition(int type);

    void DelayRefreshFormsOnAppUpgrade(const std::vector<FormRecord> &updatedForms, const Want &want);

    // ==================== Visibility Management ====================

    ErrCode NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType);

    bool HasFormVisible(const uint32_t tokenId);

    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken);

    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
        const sptr<IRemoteObject> &callerToken);

    void HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
        const sptr<IRemoteObject> &callerToken);

    void PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps);

    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds);

    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want, bool isCheckCallingUid = true);

    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked);

    // ==================== Query Management ====================

    int GetAllFormsInfo(std::vector<FormInfo> &formInfos);

    int GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos);

    int GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos);

    int GetTemplateFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos);

    int GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos);

    int GetTemplateFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos);

    int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos);

    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount);

    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount);

    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstance);

    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance);

    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos,
        const int32_t userId);

    ErrCode GetRunningFormInfosByBundleName(const std::string &bundleName, bool isUnusedIncluded,
        std::vector<RunningFormInfo> &runningFormInfos);

    ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances);

    int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo);

    int AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
        AAFwk::WantParams &formData);

    // ==================== Observer Management ====================

    ErrCode HandleFormAddObserver(const int64_t formId);

    ErrCode HandleFormRemoveObserver(const RunningFormInfo runningFormInfo);

    ErrCode RegisterFormAddObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken);

    ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken);

    ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    ErrCode RegisterClickEventObserver(const std::string &bundleName, const std::string &formEventType,
        const sptr<IRemoteObject> &observer);

    ErrCode UnregisterClickEventObserver(const std::string &bundleName, const std::string &formEventType,
        const sptr<IRemoteObject> &observer);

    void CleanResource(const wptr<IRemoteObject> &remote);

    // ==================== Event Management ====================

    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken);

    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    void SetFreeInstallFlag(const FormRecord &record, Want &want);

    bool OpenByOpenType(const int32_t openType, const FormRecord &record,
        const sptr<IRemoteObject> &callerToken, Want &want, int32_t &openResult);

    // ==================== Publish Management ====================

    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies = {}, bool needCheckFormPermission = true);

    ErrCode QueryPublishFormToHost(Want &want);

    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo);

    ErrCode AcquireAddFormResult(const int64_t formId);

    bool IsRequestPublishFormSupported();

    ErrCode StartAbilityByFms(const Want &want);

    // ==================== Callback Management ====================

    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds);

    int32_t RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    int32_t UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    ErrCode RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterOverflowProxy();

    ErrCode RequestOverflow(const int64_t formId, const int32_t callingUid,
        const OverflowInfo &overflowInfo, bool isOverflow = true);

    ErrCode RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterChangeSceneAnimationStateProxy();

    ErrCode ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state);

    ErrCode RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterGetFormRectProxy();

    ErrCode GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect);

    ErrCode RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterGetLiveFormStatusProxy();

    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap);

    ErrCode RegisterPublishFormCrossBundleControl(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterPublishFormCrossBundleControl();

    bool PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo);

    ErrCode RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterTemplateFormDetailInfoChange();

    ErrCode UpdateTemplateFormDetailInfo(const std::vector<TemplateFormDetailInfo> &templateFormInfo);

    // ==================== Debug/Dump Management ====================

    int DumpStorageFormInfos(std::string &formInfos) const;

    int DumpTemporaryFormInfos(std::string &formInfos) const;

    int DumpStaticBundleFormInfos(std::string &formInfos) const;

    int DumpHasFormVisible(const std::string &bundleInfo, std::string &formInfos) const;

    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const;

    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const;

    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const;

    int DumpFormRunningFormInfos(std::string &runningFormInfosResult) const;

private:
    FormLifecycleAdapter* lifecycleAdapter_;
    FormDataAdapter* dataAdapter_;
    FormVisibilityAdapter* visibilityAdapter_;
    FormQueryAdapter* queryAdapter_;
    FormEventAdapter* eventAdapter_;
    FormObserverAdapter* observerAdapter_;
    FormPublishAdapter* publishAdapter_;
    FormCallbackAdapter* callbackAdapter_;
    FormDebugAdapter* debugAdapter_;
    FormCommonAdapter* commonAdapter_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_MGR_ADAPTER_FACADE_H