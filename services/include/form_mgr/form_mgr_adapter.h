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

#ifndef OHOS_FORM_FWK_FORM_MGR_ADAPTER_H
#define OHOS_FORM_FWK_FORM_MGR_ADAPTER_H

#include <singleton.h>

#include "app_mgr_interface.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "form_constants.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "data_center/form_info/form_item_info.h"
#include "form_js_info.h"
#include "form_provider_data.h"
#include "form_publish_interceptor_interface.h"
#include "common/util/form_serial_queue.h"
#include "form_state_info.h"
#include "iremote_object.h"
#include "running_form_info.h"
#include "want.h"
#include "configuration.h"
#include "form_major_info.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

enum class AddFormResultErrorCode : int8_t {
    UNKNOWN = 0,
    SUCCESS,
    FAILED,
    TIMEOUT
};

/**
 * @class FormMgrAdapter
 * Form request handler from form host.
 */
class FormMgrAdapter  final : public DelayedRefSingleton<FormMgrAdapter> {
DECLARE_DELAYED_REF_SINGLETON(FormMgrAdapter)
public:
    DISALLOW_COPY_AND_MOVE(FormMgrAdapter);

    /**
     * @brief Init properties like visibleNotifyDelayTime.
     */
    void Init();

    /**
     * @brief Query the request host.
     * @param want The want of the form to publish.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryPublishFormToHost(Want &want);

    /**
     * @brief Add form with want, send want to form manager service.
     * @param formId The Id of the forms to add.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo);

    /**
     * @brief Add form with want, send want to form manager service.
     * @param want The want of the form to add.
     * @param runningFormInfo Running form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int CreateForm(const Want &want, RunningFormInfo &runningFormInfo);

    /**
     * @brief Delete forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to delete.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Stop rendering form.
     * @param formId The Id of the forms to delete.
     * @param compId The compId of the forms to delete.
     * @return Returns ERR_OK on success, others on failure.
     */
    int StopRenderingForm(const int64_t formId, const std::string &compId);

    /**
     * @brief Release forms with formIds, send formIds to form Mgr service.
     * @param formId The Id of the forms to release.
     * @param callerToken Caller ability token.
     * @param delCache Delete Cache or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache);

    /**
     * @brief Update form with formId.
     * @param formId The Id of the form to update.
     * @param callingUid Provider ability uid.
     * @param formProviderData form provider data.
     * @param std::vector<FormDataProxy> Form proxy vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    int UpdateForm(const int64_t formId, const int32_t callingUid, const FormProviderData &formProviderData,
        const std::vector<FormDataProxy> &formDataProxies = {});

    /**
     * @brief Request form with formId and want, send formId and want to form manager service.
     *
     * @param formId The Id of the form to update.
     * @param callerToken Caller ability token.
     * @param want The want of the form to request.
     * @return Returns ERR_OK on success, others on failure.
     */
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want);

    /**
     * @brief Form visible/invisible notify, send formIds to form manager service.
     *
     * @param formIds The vector of form Ids.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        const int32_t formVisibleType);

    /**
     * @brief Query whether has visible form by tokenId.
     * @param tokenId Unique identification of application.
     * @return Returns true if has visible form, false otherwise.
     */
    bool HasFormVisible(const uint32_t tokenId);

    /**
     * @brief Padding the formInstances map for visibleNotify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param formId Form Id.
     * @param formInstanceMaps formInstances for visibleNotify.
     */
    void PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps);

    /**
     * @brief temp form to normal form.
     * @param formId The Id of the form.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Dump all of form storage infos.
     * @param formInfos All of form storage infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpStorageFormInfos(std::string &formInfos) const;
    /**
     * @brief Dump all of temporary form infos.
     * @param formInfos All of temporary form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpTemporaryFormInfos(std::string &formInfos) const;
    /**
     * @brief Dump form infos of all bundles, this is static info.
     * @param formInfos All of static form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpStaticBundleFormInfos(std::string &formInfos) const;

    /**
     * @brief Dump has form visible with bundleInfo.
     * @param bundleInfo Bundle info like bundleName_userId_instIndex.
     * @param formInfos Form dump infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpHasFormVisible(const std::string &bundleInfo, std::string &formInfos) const;

    /**
     * @brief Dump form info by a bundle name.
     * @param bundleName The bundle name of form provider.
     * @param formInfos Form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) const;
    /**
     * @brief Dump form info by a bundle name.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) const;
    /**
     * @brief Dump form timer by form id.
     * @param formId The id of the form.
     * @param isTimingService "true" or "false".
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) const;

    /**
     * @brief Dump running form info.
     * @param runningFormInfosResult The dump info of all the running form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormRunningFormInfos(std::string &runningFormInfosResult) const;

    /**
     * @brief set next refresh time.
     * @param formId The id of the form.
     * @param nextTime next refresh time.
     * @return Returns ERR_OK on success, others on failure.
     */
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime);

    /**
     * @brief Release renderer.
     * @param formId The Id of the forms to release.
     * @param compId The compId of the forms to release.
     * @return Returns ERR_OK on success, others on failure.
     */
    int ReleaseRenderer(int64_t formId, const std::string &compId);

    /**
     * @brief Request to publish a form to the form host.
     *
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried with.
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @param needCheckFormPermission Indicates whether the app have system permissions.default value is true.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies = {}, bool needCheckFormPermission = true);

    ErrCode StartAbilityByFms(const Want &want);

    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo);

    ErrCode AcquireAddFormResult(const int64_t formId);
    /**
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    bool IsRequestPublishFormSupported();

    /**
     * @brief enable update form.
     * @param formIDs The id of the forms.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int EnableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief disable update form.
     * @param formIDs The id of the forms.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DisableUpdateForm(const std::vector<int64_t> formIDs, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Process js router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Process background router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Delete the invalid forms.
     * @param formIds Indicates the ID of the valid forms.
     * @param callerToken Caller ability token.
     * @param numFormsDeleted Returns the number of the deleted forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                           int32_t &numFormsDeleted);

    /**
     * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
     * @param want Indicates a set of parameters to be transparently passed to the form provider.
     * @param callerToken Caller ability token.
     * @param stateInfo Returns the form's state info of the specify.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo);

    /**
     * @brief Acquire form data by formId.
     * @param formId The Id of the form to acquire data.
     * @param callerToken Indicates the host client.
     * @param requestCode The request code of this acquire form.
     * @param formData Return the forms' information of customization
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData);

    /**
     * @brief Notify the form is visible or not.
     * @param formIds Indicates the ID of the forms.
     * @param isVisible Visible or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Notify the form is enable to be updated or not.
     * @param formIds Indicates the ID of the forms.
     * @param isEnableUpdate enable update or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                const sptr<IRemoteObject> &callerToken);

    /**
      * @brief Get All FormsInfo.
      * @param formInfos Return the forms' information of all forms provided.
      * @return Returns ERR_OK on success, others on failure.
      */
    int GetAllFormsInfo(std::vector<FormInfo> &formInfos);

    /**
     * @brief Get forms info by bundle name .
     * @param bundleName Application name.
     * @param formInfos Return the forms' information of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos);

    /**
     * @brief Get forms info by bundle name and module name.
     * @param bundleName bundle name.
     * @param moduleName Module name of hap.
     * @param formInfos Return the forms' information of the specify bundle name and module name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos);

    /**
     * @brief Get forms info specfied by filter parameters.
     * @param filter Filter that contains necessary conditions, such as bundle name, module name, dimensions.
     * @param formInfos Return the forms' information specified by filter.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos);

    /**
    * @brief get forms count.
    * @param isTempFormFlag Indicates temp form or not.
    * @param formCount Returns the number of the cast or temp form.
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount);

    /**
    * @brief get host forms count.
    * @param bundleName Indicates form host bundleName.
    * @param formCount Returns the number of the host form.
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount);

    /**
     * @brief Handle form add observer.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleFormAddObserver(const int64_t formId);

    /**
     * @brief Handle form add observer.
     * @param runningFormInfo the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleFormRemoveObserver(const RunningFormInfo runningFormInfo);

    /**
     * @brief Register form add observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormAddObserverByBundle(const std::string bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Register form remove observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Get all running form infos.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos currently.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos);

    /**
     * @brief Get the running form infos by bundle name.
     * @param bundleName Application name.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos);

    /**
     * @brief Get form instances by filter info.
     * @param formInstancesFilter includes bundleName, moduleName, formName, abilityName to get formInstances.
     * @param formInstances return formInstances
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances);

    /**
     * @brief Get form instance by formId.
     * @param formId formId Indicates the unique id of form.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstance);

    /**
     * @brief Get form instance by formId, include form store in DB.
     * @param formId formId Indicates the unique id of form.
     * @param isUnusedIncluded Indicates whether to include unused form.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance);

    /**
     * @brief Register form add observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Register form remove observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Register form router event proxy.
     * @param formIds Indicates the ID of the forms.
     * @param callerToken Router proxy call back client.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister form router event proxy.
     * @param formIds Indicates the ID of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds);

    /**
     * @brief Registers the callback for publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    /**
     * @brief Unregisters the callback for publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    /**
     * @brief Register click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer);

    /**
     * @brief Unregister click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer);

    /**
     * @brief Compare the locally configured update duration with the update duration in additionalInfo and
     * return a larger value.
     * @param formId The Id of the form.
     * @param updateDuration The valid form update duration.
     * @return Returns true on success, false on failure.
     */
    bool GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const;

    /**
     * @brief Handle forms visible/invisible notify after delay time, notification will be cancelled when
     * formVisibleState recovered during the delay time.
     * @param formIds the Ids of forms need to notify.
     * @param formInstanceMaps formInstances for visibleNotify.
     * @param eventMaps eventMaps for event notify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param callerToken Caller ability token.
     */
    void HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
        const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Set forms recyclable
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds);

    /**
     * @brief Recycle forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recycled.
     * @param isCheckCallingUid is need check CallingUid, default is true.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want, bool isCheckCallingUid = true);

    /**
     * @brief Recover recycled forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recovered.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want);

    /**
     * @brief Update form cloud update duration when additionalInfo changed.
     * @param bundleName The bundleName of the form with a specified update duration in app gallery.
     */
    void UpdateFormCloudUpdateDuration(const std::string &bundleName);

    /**
    * @brief Update formLocation with formId.
    * @param formId The Id of the form to update.
    * @param formLocation formLocation.
    * @param isRequestPublishFormWithSnapshot is request publish form with snapshot, default is false.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation,
        const bool isRequestPublishFormWithSnapshot = false);

    /**
     * @brief Update form with formRefreshType, send to form manager service.
     * @param formRefreshType The type of the form to refresh, 0: AllForm 1: 2: AppForm 2: AtomicServiceForm
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode BatchRefreshForms(const int32_t formRefreshType);

    /**
     * @brief notify formAbility when system configuration changed.
     * @param configuration system config
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode BatchNotifyFormsConfigurationUpdate(const AppExecFwk::Configuration &configuration);
#ifdef RES_SCHEDULE_ENABLE
    /**
     * @brief Set the value which indicate whether Refresh Timer task should be triggered.
     * @param isTimerTaskNeeded The value of whether Refresh Timer task should be triggered.
     */
    void SetTimerTaskNeeded(bool isTimerTaskNeeded);
#endif // RES_SCHEDULE_ENABLE

    /**
     * @brief enable/disable form update.
     * @param bundleName BundleName of the form host.
     * @param enable True for enable form, false for disable form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t EnableForms(const std::string bundleName, const int32_t userId, const bool enable);

    /**
     * @brief this interface is invoked when the application lock status changes.
     * @param bundleName BundleName of the form host.
     * @param lock True for lock bundle, false for unlock bundle.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SwitchLockForms(const std::string &bundleName, int32_t userId, const bool lock);

    /**
     * @brief this interface is invoked when the application protect status changes.
     * @param bundleName BundleName of the form host.
     * @param lock True for protect form, false for unprotect form.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ProtectLockForms(const std::string &bundleName, int32_t userId, const bool protect);

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param width The width value to be updated.
     * @param height The height value to be updated.
     * @param borderWidth The borderWidth value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth);

    int32_t OnNotifyRefreshForm(const int64_t &formId);

    /**
     * @brief Update form by condition.
     * @param UpdateType The type of the form to update.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormByCondition(int type);

    /**
     * @brief Notify the form is locked or not.
     * @param formId Indicates the ID of the form.
     * @param isLocked locked or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked);

    /**
     * @brief Register overflow proxy
     * @param callerToken The form host proxy
     * @return Return true for overflow proxy register success, false otherwise
     */
    bool RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister overflow proxy
     * @return Return true for overflow proxy unregister success, false otherwise
     */
    bool UnregisterOverflowProxy();

    /**
     * @brief Request overflow with specific range
     * @param formId The id of the form to request overflow
     * @param callingUid Provider ability uid.
     * @param overflowInfo The overflowInfo to explict overflow area and duration
     * @param isOverflow True for request overflow, false for cancel overflow, default value is true
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode RequestOverflow(const int64_t formId, const int32_t callingUid,
        const OverflowInfo &overflowInfo, bool isOverflow = true);

    /**
     * @brief Register change sceneAnimation state proxy
     * @param callerToken The form host proxy.
     * @return Returns true for change sceneAnimation state proxy register success, false otherwise
     */
    bool RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister change sceneAnimation state proxy
     * @return Return true for change sceneAnimation state proxy unregister success, false otherwise
     */
    bool UnregisterChangeSceneAnimationStateProxy();

    /**
     * @brief Change SceneAnimation State.
     * @param formId The formId.
     * @param callingUid Provider ability uid.
     * @param state 1 for activate SceneAnimation, 0 for deactivate SceneAnimation
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state);

    /**
     * @brief Set get form rect proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK for setting success.
     */
    bool RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister get form rect proxy in fms
     * @return Return true if unregister success
     */
    bool UnregisterGetFormRectProxy();

    /**
     * @brief Get the form rect.
     * @param formId The formId.
     * @param callingUid Provider ability uid.
     * @param rect The desktop's rect related to the specified formId.
     * @return Returns error code of method execute, which ERR_OK represents success.
     */
    ErrCode GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect);

    /**
     * @brief Set get live form status proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK for setting success.
     */
    bool RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister get live form status proxy in fms
     * @return Return true if unregister success
     */
    bool UnregisterGetLiveFormStatusProxy();

    /**
     * @brief Get live form status.
     * @param liveFormStatusMap The Map that stores formId and live form status.
     * @return Returns error code of method execute, which ERR_OK represents success.
     */
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap);

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect);

    /**
     * @brief Delay refresh forms task when provider update.
     * @param updatedForms Need refresh forms.
     * @param want The want of the request.
     * @return Returns ERR_OK on success, others on failure.
     */
    void DelayRefreshForms(const std::vector<FormRecord> &updatedForms, const Want &want);

    /**
     * @brief Reacquire form info from form provider.
     * @param formId The Id of the form.
     * @param info Form configure info.
     * @param wantParams WantParams of the request.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ReAcquireProviderFormInfoAsync(const FormItemInfo &info, const WantParams &wantParams);

    /**
     * @brief Clear reconnect num.
     * @param formId The Id of the form.
     */
    void ClearReconnectNum(int64_t formId);

    /**
    * @brief Reload specified forms of application.
    * @param reloadNum The number of forms to be updated.
    * @param refreshForms The vector of forms to be updated.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode ReloadForms(int32_t &reloadNum, const std::vector<FormRecord> &refreshForms);

    /**
     * @brief Check form is due control.
     * @param formMajorInfo form major info.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @return Returns true for form is due controlled.
     */
    bool CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy);
private:
    /**
     * @brief Get form configure info.
     * @param want The want of the request.
     * @param formItemInfo Form configure info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetFormConfigInfo(const Want& want, FormItemInfo &formItemInfo);

    /**
     * @brief Get bundle info.
     * @param want The want of the request.
     * @param bundleInfo Bundle info.
     * @param packageName Package name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetBundleInfo(const AAFwk::Want &want, BundleInfo &bundleInfo, std::string &packageName);

    /**
     * @brief Get form info.
     * @param want The want of the request.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetFormInfo(const AAFwk::Want &want, FormInfo &formInfo);

    /**
     * @brief Get form configure info.
     * @param want The want of the request.
     * @param bundleInfo Bundle info.
     * @param formInfo Form info.
     * @param formItemInfo Form configure info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetFormItemInfo(const AAFwk::Want &want, const BundleInfo &bundleInfo, const FormInfo &formInfo,
        FormItemInfo &formItemInfo);

    /**
     * @brief Dimension valid check.
     * @param formInfo Form info.
     * @param dimensionId Dimension id.
     * @return Returns true on success, false on failure.
     */
    bool IsDimensionValid(const FormInfo &formInfo, int dimensionId) const;

    /**
     * @brief Create form configure info.
     * @param bundleInfo Bundle info.
     * @param formInfo Form info.
     * @param itemInfo Form configure info.
     * @param want The want of the request.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CreateFormItemInfo(const BundleInfo& bundleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo,
        const AAFwk::Want &want);

    /**
     * @brief Set form item info params.
     * @param bundleInfo Bundle info.
     * @param formInfo Form info.
     * @param itemInfo Form item info.
     */
    void SetFormItemInfoParams(const BundleInfo& bundleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo);

    /**
     * @brief Set form item module info.
     * @param hapModuleInfo Hap module info.
     * @param formInfo Form info.
     * @param itemInfo Form item info.
     */
    void SetFormItemModuleInfo(const HapModuleInfo& hapModuleInfo, const FormInfo& formInfo,
        FormItemInfo& itemInfo);

    /**
     * @brief Allocate form by formId.
     * @param info Form configure info.
     * @param callerToken Caller ability token.
     * @param wantParams WantParams of the request.
     * @param formInfo Form info for form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AllotFormById(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const WantParams &wantParams, FormJsInfo &formInfo);

    /**
     * @brief Allocate form by form configure info.
     * @param info Form configure info.
     * @param callerToken Caller ability token.
     * @param wantParams WantParams of the request.
     * @param formInfo Form info for form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AllotFormByInfo(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const WantParams& wantParams, FormJsInfo &formInfo);

    /**
     * @brief Acquire form data from form provider.
     * @param formId The Id of the form.
     * @param info Form configure info.
     * @param wantParams WantParams of the request.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AcquireProviderFormInfoAsync(const int64_t formId, const FormItemInfo &info, const WantParams &wantParams);

    ErrCode InnerAcquireProviderFormInfoAsync(const int64_t formId,
        const FormItemInfo &info, const WantParams &wantParams);

    /**
     * @brief Handle release form.
     * @param formId The form id.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Handle delete form.
     * @param formId The form id.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleDeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Handle delete temp form.
     * @param formId The form id.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleDeleteTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Handle delete form storage.
     * @param dbRecord Form storage information.
     * @param uid calling user id.
     * @param formId The form id.
     * @return Function result and has other host flag.
     */
    ErrCode HandleDeleteFormCache(FormRecord &dbRecord, const int uid, const int64_t formId);

    /**
     * @brief Add existed form record.
     * @param info Form configure info.
     * @param callerToken Caller ability token.
     * @param record Form data.
     * @param formId The form id.
     * @param wantParams WantParams of the request.
     * @param formInfo Form info for form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddExistFormRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callerToken,
        const FormRecord &record, const int64_t formId, const WantParams &wantParams, FormJsInfo &formInfo);

    /**
     * @brief Add new form record.
     * @param info Form configure info.
     * @param formId The form id.
     * @param callerToken Caller ability token.
     * @param wantParams WantParams of the request.
     * @param formInfo Form info for form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddNewFormRecord(const FormItemInfo &info, const int64_t formId,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo);

    /**
     * @brief Send event notify to form provider. The event notify type include FORM_VISIBLE and FORM_INVISIBLE.
     *
     * @param providerKey The provider key string which consists of the provider bundle name and ability name.
     * @param formIdsByProvider The map of form Ids and their event type which have the same provider.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleEventNotify(const std::string &providerKey, const std::vector<int64_t> &formIdsByProvider,
        const int32_t formVisibleType);

    /**
     * @brief Increase the timer refresh count.
     *
     * @param formId The form id.
     */
    void IncreaseTimerRefreshCount(const int64_t formId);

    /**
     * @brief handle update form flag.
     * @param formIDs The id of the forms.
     * @param callerToken Caller ability token.
     * @param flag form flag.
     * @param isOnlyEnableUpdate form enable update form flag.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleUpdateFormFlag(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                 bool flag, bool isOnlyEnableUpdate);

    /**
     * @brief check form cached.
     * @param record Form information.
     * @return Returns true on cached, false on not.
     */
    bool IsFormCached(const FormRecord record);

    /**
     * @brief check if update is valid.
     * @param formId The form's id.
     * @param bundleName Provider ability bundleName.
     * @return Returns true or false.
     */
    bool IsUpdateValid(const int64_t formId, const std::string &bundleName);
    /**
     * @brief Handle cast temp form.
     * @param formId The form id.
     * @param record Form information.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode HandleCastTempForm(const int64_t formId, const FormRecord &record);

    /**
     * @brief Add form timer.
     * @param formRecord Form information.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddFormTimer(const FormRecord &formRecord);

    /**
     * @brief Genera checking the publish form.
     * @param want The want of the form to publish.
     * @param bundleName BundleName
     * @param needCheckFormPermission Indicates whether the app have system permissions.default value is true.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CheckFormBundleName(Want &want, std::string &bundleName, bool needCheckFormPermission);

    /**
     * @brief check the publish form.
     * @param want The want of the form to publish.
     * @param needCheckFormPermission Indicates whether the app have system permissions.default value is true.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CheckPublishForm(Want &want, bool needCheckFormPermission = true);

    /**
     * @brief Post request publish form to host.
     * @param want The want of the form to publish.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestPublishFormToHost(Want &want);

    /**
     * @brief check request publish form want.
     * @param want The want of the form to publish.
     * @return Returns true if have snapshot info, others on none.
     */
    bool CheckSnapshotWant(const Want &want);

    /**
     * @brief check the argv of AddRequestPublishForm.
     * @param want The want of the form to add.
     * @param formProviderWant The want of the form to publish from provider.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode CheckAddRequestPublishForm(const Want &want, const Want &formProviderWant);

    /**
     * @brief add request publish form.
     * @param formItemInfo Form configure info.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formJsInfo Return form info to form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AddRequestPublishForm(const FormItemInfo &formItemInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formJsInfo);

    /**
     * @brief get bundleName.
     * @param bundleName for output.
     * @param needCheckFormPermission Indicates whether the app have system permissions.default value is true.
     * @return Returns true on success, others on failure.
     */
    bool GetBundleName(std::string &bundleName, bool needCheckFormPermission = true);

    /**
     * @brief Check if the form should update information to the host.
     *
     * @param matchedFormId The Id of the form
     * @param userId User ID.
     * @param callerToken Caller ability token.
     * @param formRecord Form storage information
     * @return Returns true on success, false on failure.
     */
    bool isFormShouldUpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
        const sptr<IRemoteObject> &callerToken, FormRecord &formRecord);

    /**
     * @brief Update provider info to host
     *
     * @param matchedFormId The Id of the form
     * @param userId User ID.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param formRecord Form storage information
     * @return Returns true on success, false on failure.
     */
    bool UpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
        const sptr<IRemoteObject> &callerToken, const int32_t &formVisibleType, FormRecord &formRecord);

    /**
     * @brief if the ability have permission for keeping background running is true,
     * @param iBundleMgr BundleManagerProxy
     * @param bundleName BundleName
     * @param userId UserId
     * @return Returns true if the form provider is system app, false if not.
     */
    bool CheckIsSystemAppByBundleName(const sptr<IBundleMgr> &iBundleMgr,
        const int32_t &userId, const std::string &bundleName);

    /**
     * @brief if the ability have permission for keeping background running is true,
     * @param iBundleMgr BundleManagerProxy
     * @param bundleName BundleName
     * @return Returns true if the ability have permission for keeping background running, false if not.
     */
    bool CheckKeepBackgroundRunningPermission(const sptr<IBundleMgr> &iBundleMgr, const std::string &bundleName);
    /**
     * @brief Create eventMaps for event notify.
     *
     * @param matchedFormId The Id of the form
     * @param formRecord Form storage information
     * @param eventMaps eventMaps for event notify
     * @return Returns true on success, false on failure.
     */
    bool CreateHandleEventMap(const int64_t matchedFormId, const FormRecord &formRecord,
        std::map<std::string, std::vector<int64_t>> &eventMaps);

    /**
     * @brief AcquireFormState want check.
     * @param bundleName The bundle name of the form.
     * @param abilityName The ability name of the form.
     * @param want The want of the form.
     * @param provider the provider info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AcquireFormStateCheck(const std::string &bundleName, const std::string &abilityName, const Want &want,
                                  std::string &provider);
    /**
     * @brief check if the form host is system app
     * @param formRecord Form storage information
     * @return Returns true if the form host is system app, false if not.
     */
    bool checkFormHostHasSaUid(const FormRecord &formRecord);

    /**
     * @brief Check whether the caller for publish form is in the whitelist.
     * @param iBundleMgr BundleManagerProxy
     * @param bundleName BundleName of caller
     * @param want want of target form
     * @param needCheckFormPermission Indicates whether the app have system permissions.default value is true.
     * @return Returns true if the caller is in the whitelist, others if not.
     */
    bool IsValidPublishEvent(const sptr<IBundleMgr> &iBundleMgr, const std::string &bundleName, const Want &want,
        bool needCheckFormPermission = true);

    /**
     * @brief Allocate form by specific Id.
     * @param info Form configure info.
     * @param callerToken Caller ability token.
     * @param wantParams WantParams of the request.
     * @param formInfo Form info for form host.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode AllotFormBySpecificId(const FormItemInfo &info,
        const sptr<IRemoteObject> &callerToken, const WantParams &wantParams, FormJsInfo &formInfo);

    /**
     * @brief when form observer died clean the resource.
     * @param remote remote object.
     */
    void CleanResource(const wptr<IRemoteObject> &remote);

    /**
     * @brief Set value of deathRecipient_.
     * @param callerToken Caller ability token.
     * @param deathRecipient DeathRecipient object.
     */
    void SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
        const sptr<IRemoteObject::DeathRecipient> &deathRecipient);
    mutable std::mutex formObserversMutex_;
    mutable std::mutex deathRecipientsMutex_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formObservers_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;

    void NotifyFormClickEvent(int64_t formId, const std::string &formClickType);

    /**
     * @brief Get caller type.
     * @param bundleName the caller's bundle name.
     */
    int32_t GetCallerType(std::string bundleName);

    /**
     * @brief Check if the form is allow to publish.
     * @param bundleName the caller's bundle name.
     * @param wants Wants of the request.
     */
    bool IsErmsSupportPublishForm(std::string bundleName, std::vector<Want> wants);

    /**
     * @brief Check if the caller is formRenderService.
     * @param callingUid the caller's Uid.
     * @return Returns true if the caller is formRenderService, false if not.
     */
    bool IsFormRenderServiceCall(int callingUid);

    /**
     * @brief Notify forms visible/invisible to remoteCallers.
     * @param bundleName the caller's bundle name.
     * @param remoteObjects refs of remoteCallers.
     * @param formInstanceMaps formInstances for visibleNotify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     */
    void NotifyWhetherFormsVisible(const std::string &bundleName,
        const std::vector<sptr<IRemoteObject>> &remoteObjects,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps, const int32_t formVisibleType);

    /**
     * @brief Forms formInstanceMaps or eventMaps should remove when visible/invisible status recovered.
     * @param formInstanceMaps formInstances for visibleNotify.
     * @param eventMaps eventMaps for event notify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     */
    void FilterDataByVisibleType(std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> &eventMaps, const int32_t formVisibleType);

    /**
     * @brief Forms formInstanceMaps should remove when visible/invisible status recovered.
     * @param formInstanceMaps formInstances for visibleNotify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param restoreFormRecords formRecords of forms no need to notify.
     */
    void FilterFormInstanceMapsByVisibleType(std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords);

    /**
     * @brief Forms eventMaps should remove when visible/invisible status recovered.
     * @param eventMaps eventMaps for event notify.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param restoreFormRecords formRecords of forms no need to notify.
     */
    void FilterEventMapsByVisibleType(std::map<std::string, std::vector<int64_t>> &eventMaps,
        const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords);

    ErrCode CheckFormCountLimit(const int64_t formId, const Want &want);

    ErrCode AllotForm(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken, FormJsInfo &formInfo, const FormItemInfo &formItemInfo);

    void GetUpdateDurationFromAdditionalInfo(const std::string &additionalInfo, std::vector<int> &durationArray) const;

    void IncreaseAddFormRequestTimeOutTask(const int64_t formId);

    void CancelAddFormRequestTimeOutTask(const int64_t formId, const int result);

    ErrCode CheckAddFormTaskTimeoutOrFailed(const int64_t formId, AddFormResultErrorCode &formStates);

    void RemoveFormIdMapElement(const int64_t formId);

    void UpdateReUpdateFormMap(const int64_t formId);

    void SetReUpdateFormMap(const int64_t formId);

    ErrCode UpdateTimer(const int64_t formId, const FormRecord &record);

    void SetFormEnableAndLockState(FormInfo &formInfo, FormItemInfo &formConfigInfo, int formLocation);

    void SetLockFormStateOfFormItemInfo(FormInfo &formInfo, FormItemInfo &formConfigInfo);

    bool IsActionAllowToPublish(const std::string &action);

    /**
     * @brief Get form info by form record.
     * @param record The record of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetFormInfoByFormRecord(const FormRecord &record, FormInfo &formInfo);

    /**
     * @brief Get calling user ID.
     * @return Returns user ID.
     */
    int32_t GetCallingUserId();
    /**
     * @class ClientDeathRecipient
     * notices IRemoteBroker died.
     */
    class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        /**
         * @brief Constructor
         */
        ClientDeathRecipient() = default;
        virtual ~ClientDeathRecipient() = default;
        /**
         * @brief handle remote object died event.
         * @param remote remote object.
         */
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    /**
     * @brief Check sceneAnimation request parameter legitimacy.
     * @param formId The formId.
     * @param callingUid Provider ability uid.
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode SceneAnimationCheck(const int64_t formId, const int32_t callingUid);

    /**
     * @brief Check caller parameter legitimacy.
     * @param formId The formId.
     * @param callingUid Provider ability uid.
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode CallerCheck(const int64_t formId, const int32_t callingUid);

private:
    sptr<IFormPublishInterceptor> formPublishInterceptor_ = nullptr;
    std::mutex formPublishInterceptorMutex_;
    int32_t visibleNotifyDelay_ = Constants::DEFAULT_VISIBLE_NOTIFY_DELAY;
    std::map<int64_t, AddFormResultErrorCode> formIdMap_;
    std::unique_ptr<FormSerialQueue> serialQueue_ = nullptr;
    std::mutex formResultMutex_;
    std::condition_variable condition_;
    std::map<int64_t, int32_t> formReconnectMap_;
    std::mutex reconnectMutex_;
#ifdef THEME_MGR_ENABLE
    /**
     * @brief Call ThemeManager to delete form and clear record in database.
     * @param formId Indicates the id of form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteThemeForm(const int64_t formId);

    /**
     * @brief Add theme form record in database.
     * @param want The want of form.
     * @param formId Indicates the id of form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AddThemeDBRecord(const Want &want, int64_t formId);

    /**
     * @brief Allot theme form record in FormDataMgr.
     * @param want The want of form.
     * @param formId Indicates the id of form.
     * @return Returns formrecord created.
     */
    FormRecord AllotThemeRecord(const Want &want, int64_t formId);
#endif

    /**
     * @brief Delete common forms with formId.
     * @param formId Indicates the id of form.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteCommonForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    void CheckUpdateFormRecord(const int64_t formId, const FormItemInfo &info, FormRecord &record);

    void SetVisibleChange(const int64_t formId, const int32_t formVisibleType);

    /**
    * @brief Post Form visible/invisible notify.
    * @param formIds  the Ids of forms need to notify.
    * @param formInstanceMaps formInstances for visibleNotify.
    * @param eventMaps eventMaps for event notify.
    * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
    * @param visibleNotifyDelay delay time.
    * @param callerToken Caller ability token.
    */
    void PostVisibleNotify(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> &eventMaps,
        const int32_t formVisibleType, int32_t visibleNotifyDelay,
        const sptr<IRemoteObject> &callerToken);

    sptr<OHOS::AppExecFwk::IAppMgr> GetAppMgr();

    void PostEnterpriseAppInstallFailedRetryTask(const FormRecord &record, const Want &want);

    bool IsForegroundApp();

    void SetFormPublishInterceptor(const sptr<IFormPublishInterceptor> &formPublishInterceptor);

    sptr<IFormPublishInterceptor> GetFormPublishInterceptor();

    std::mutex reUpdateFormMapMutex_;
    std::unordered_map<int64_t, std::pair<int64_t, bool>> reUpdateFormMap_;

    std::map<int, std::vector<int64_t>> conditionUpdateFormMap;

    sptr<IRemoteObject> overflowCallerToken_;

    sptr<IRemoteObject> sceneanimationCallerToken_;

    sptr<IRemoteObject> getFormRectCallerToken_;

    sptr<IRemoteObject> getLiveFormStatusCallerToken_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_MGR_ADAPTER_H
