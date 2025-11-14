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

#ifndef OHOS_FORM_FWK_FORM_MGR_H
#define OHOS_FORM_FWK_FORM_MGR_H

#include <mutex>
#include <shared_mutex>
#include <singleton.h>
#include <thread>

#include "form_callback_interface.h"
#include "form_constants.h"
#include "form_errors.h"
#include "form_death_callback.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_js_info.h"
#include "form_mgr_interface.h"
#include "form_provider_data.h"
#include "form_provider_data_proxy.h"
#include "form_state_info.h"
#include "running_form_info.h"
#include "iremote_object.h"
#include "want.h"
#include "form_major_info.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;

/**
 * @class FormMgr
 * FormMgr is used to access form manager services.
 */
class FormMgr final : public DelayedRefSingleton<FormMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormMgr);

    friend class FormMgrDeathRecipient;

    /**
     * @brief Register click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer);

    /**
     * @brief Unregister click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer);

    /**
     * @brief Get the error message by error code.
     * @param errorCode the error code return form fms.
     * @return Returns the error message detail.
     */
    std::string GetErrorMsg(int errorCode);

    /**
     * @brief Add form with want, send want to form manager service.
     * @param formId The Id of the forms to add.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
        FormJsInfo &formInfo);

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
     * @brief Release forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to release.
     * @param callerToken Caller ability token.
     * @param delCache Delete Cache or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache);

    /**
     * @brief Update form with formId, send formId to form manager service.
     * @param formId The Id of the form to update.
     * @param formBindingData Form binding data.
     * @param std::vector<FormDataProxy> Form proxy vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    int UpdateForm(const int64_t formId, const FormProviderData &formBindingData,
        const std::vector<FormDataProxy> &formDataProxies = {});

    /**
     * @brief Notify the form service that the form user's lifecycle is updated.
     *
     * This should be called when form user request form.
     *
     * @param formId Indicates the unique id of form.
     * @param callerToken Indicates the callback remote object of specified form user.
     * @param want information passed to supplier.
     * @return Returns ERR_OK on success, others on failure.
     */
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want);

    /**
     * @brief Form visible/invisible notify, send formIds to form manager service.
     * @param formIds The Id list of the forms to notify.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
    const int32_t formVisibleType);

    /**
     * @brief Query whether has visible form by tokenId.
     * @param tokenId Unique identification of application.
     * @return Returns true if has visible form, false otherwise.
     */
    bool HasFormVisible(const uint32_t tokenId);

    /**
     * @brief Release renderer.
     * @param formId The Id of the forms to release.
     * @param compId The compId of the forms to release.
     * @return Returns ERR_OK on success, others on failure.
     */
    int ReleaseRenderer(const int64_t formId, const std::string &compId);

    /**
     * @brief temp form to normal form.
     * @param formId The Id of the form.
     * @param callerToken Caller ability token.
     * @return None.
     */
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Dump all of form storage infos.
     * @param formInfos All of form storage infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpStorageFormInfos(std::string &formInfos);
    /**
     * @brief Dump form info by a bundle name.
     * @param bundleName The bundle name of form provider.
     * @param formInfos Form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByBundleName(const std::string bundleName, std::string &formInfos);
    /**
     * @brief Dump form info by a bundle name.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo);
    /**
     * @brief Dump form timer by form id.
     * @param formId The id of the form.
     * @param formInfo Form timer.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService);
    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Process js router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Process Background event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Get fms recoverStatus.
     *
     * @return The current recover status.
     */
    static int GetRecoverStatus();

    /**
     * @brief Register death callback.
     *
     * @param formDeathCallback The death callback.
     */
    void RegisterDeathCallback(const std::shared_ptr<FormCallbackInterface> &formDeathCallback);

    /**
     * @brief UnRegister death callback.
     *
     * @param formDeathCallback The death callback.
     */
    void UnRegisterDeathCallback(const std::shared_ptr<FormCallbackInterface> &formDeathCallback);

    /**
     * @brief Set the next refresh time
     *
     * @param formId The id of the form.
     * @param nextTime Next refresh time
     * @return Returns ERR_OK on success, others on failure.
     */
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime);

    /**
     * @brief Request to publish a form to the form host.
     *
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried with.
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies = {});

    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo);

    ErrCode AcquireAddFormResult(const int64_t formId);

    /**
     * @brief Lifecycle Update.
     * @param formIds The id of the forms.
     * @param callerToken Host client.
     * @param updateType update type, enable if true and disable if false.
     * @return Returns ERR_OK on success, others on failure.
     */
    int LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                        bool updateType);

    /**
     * @brief Set fms recoverStatus.
     *
     * @param recoverStatus The recover status.
     */
    static void SetRecoverStatus(int recoverStatus);

    /**
     * @brief Set form mgr service for test.
     */
    void SetFormMgrService(sptr<IFormMgr> formMgrService);

    /**
     * @brief Get death recipient.
     * @return deathRecipient_.
     */
    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient() const;

    /**
     * @brief Check whether the specified death callback is registered in form mgr.
     * @param formDeathCallback The specified death callback for checking.
     * @return Return true on success, false on failure.
     */
    bool CheckIsDeathCallbackRegistered(const std::shared_ptr<FormCallbackInterface> &formDeathCallback);

    /**
     * @brief Get the error message content.
     *
     * @param errCode Error code.
     * @return Message content.
     */
    std::string GetErrorMessage(int errCode);

    /**
     * @brief Delete the invalid forms.
     * @param formIds Indicates the ID of the valid forms.
     * @param callerToken Host client.
     * @param numFormsDeleted Returns the number of the deleted forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                           int32_t &numFormsDeleted);

    /**
     * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
     * @param want Indicates a set of parameters to be transparently passed to the form provider.
     * @param callerToken Host client.
     * @param stateInfo Returns the form's state info of the specify.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken, FormStateInfo &stateInfo);

    /**
     * @brief Notify the form is visible or not.
     * @param formIds Indicates the ID of the forms.
     * @param isVisible Visible or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Notify the form is privacy protected or not.
     * @param formIds Indicates the ID of the forms.
     * @param isProtected isProtected or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                    const sptr<IRemoteObject> &callerToken);

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
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos);

    /**
     * @brief Get forms info by bundle name and module name.
     * @param bundleName bundle name.
     * @param moduleName Module name of hap.
     * @param formInfos Return the forms' information of the specify bundle name and module name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByModule(std::string &bundleName, std::string &moduleName, std::vector<FormInfo> &formInfos);

    /**
     * @brief Get forms info specified by filter parameters.
     * @param filter Filter that contains necessary conditions, such as bundle name, module name, dimensions.
     * @param formInfos Return the forms' information specified by filter.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos);

    /**
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved by form service manager.
    * @param filter filter that contains attributes that the formInfos have to have.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos);

    /**
    * @brief This function is called by formProvider and gets form info by the formId of the calling ability.
    *        The formId will be retrieved by form service manager.
    * @param formId The formId of the calling ability
    * @param formInfo Return the form' information of the calling formId
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo);

    /**
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved by form service manager.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos);

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
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    bool IsRequestPublishFormSupported();

    /**
     * @brief Start an ability. This function can only be called by a form extension of a system app.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @param callerToken token of the ability that initially calls this function.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Start an ability by form manager service.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbilityByFms(const Want &want);

    /**
     * @brief Start an ability by cross bundle.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbilityByCrossBundle(const Want &want);

    /**
     * @brief Share form with formId and remote device id.
     * @param formId The Id of the forms to share.
     * @param remoteDeviceId The Id of the remote revice to share.
     * @param callerToken Indicates the host client.
     * @param requestCode The request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t ShareForm(int64_t formId, const std::string &remoteDeviceId, const sptr<IRemoteObject> &callerToken,
        int64_t requestCode);

    /**
     * @brief Acquire form data by formId.
     * @param formId The Id of the form to acquire data.
     * @param requestCode The request code of this acquire form.
     * @param callerToken Indicates the host client.
     * @param formData Return the forms' information of customization
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData);

    /**
     * @brief Check form manager service ready.
     * @return Returns ERR_OK if form manager service Ready, other values otherwise.
     */
    int32_t CheckFMSReady();

    /**
     * @brief Check whether the form is system app.
     * @param bundleName The bundleName of the form.
     * @return Returns true if the form app is system, others false.
     */
    bool IsSystemAppForm(const std::string &bundleName);

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
     * @brief Get external error from innerErrorCode.
     * @param innerErrorCode innerErrorCode, get from FMS.
     * @param externalErrorCode output externalErrorCode.
     * @param errorMsg output errorMsg.
     */
    void GetExternalError(int32_t innerErrorCode, int32_t &externalErrorCode, std::string &errorMsg);

    /**
     * @brief Get external error message by external error code.
     *
     * @param externalErrorCode External error code.
     * @return External error message.
     */
    std::string GetErrorMsgByExternalErrorCode(int32_t externalErrorCode);

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
     * @brief Set forms recyclable
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds);

    /**
     * @brief Recycle forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recycled.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want);

    /**
     * @brief Recover recycled forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recovered.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want);

    /**
     * @brief Update formLocation with formId.
     * @param formId The Id of the form to update.
     * @param formLocation The FormLocation.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation);

    /**
    * @brief Request to publish a form to the form host for normal authority.
    *
    * @param want The want of the form to publish.
    * @param withFormBindingData Indicates whether the formBindingData is carried with.
    * @param formBindingData Indicates the form data.
    * @param formId Return the form id to be published.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies = {});

    /**
     * @brief Update form with formRefreshType, send to form manager service.
     * @param formRefreshType The type of the form to refresh, 0: AllForm 1: 2: AppForm 2: AtomicServiceForm
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t BatchRefreshForms(const int32_t formRefreshType);

    /**
     * @brief Check form bundle is controlled.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle is controlled.
     */
    bool IsFormBundleForbidden(const std::string &bundleName);

    /**
     * @brief Check form bundle is protected.
     * @param bundleName The bundle name of form to be check.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is protected.
     */
    bool IsFormBundleProtected(const std::string &bundleName, int64_t formId);

    /**
     * @brief Check form bundle signature is debug.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle is debug.
     */
    bool IsFormBundleDebugSignature(const std::string &bundleName);

    /**
     * @brief Check form bundle is exempt.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is exempt.
     */
    bool IsFormBundleExempt(int64_t formId);

    /**
     * @brief Notify the form is locked or not.
     * @param formId Indicates the ID of the form.
     * @param isLocked locked or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked);

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param width The width value to be updated.
     * @param height The height value to be updated.
     * @param borderWidth The borderWidth value to be updated.
     * @param formViewScale the formViewScale value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UpdateFormSize(const int64_t formId, float width, float height, float borderWidth,
        float formViewScale);
    /**
     * @brief Open the form edit ability.
     * @param abilityName The form edit ability name.
     * @param formId The edit form ID.
     * @param isMainPage Open the main edit page.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage);

    /**
     * @brief Register overflow proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister overflow proxy in fms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterOverflowProxy();

    /**
     * @brief Request overflow with specific range.
     * @param formId The id of the form to request overflow.
     * @param overflowInfo The overflowInfo to explict overflow area and duration.
     * @param isOverflow True for request overflow, false for cancel overflow, default value is true.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow = true);

    /**
     * @brief Register change sceneAnimation state proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister change sceneAnimation state proxy in fms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterChangeSceneAnimationStateProxy();

    /**
     * @brief Change SceneAnimation State.
     * @param formId The formId.
     * @param state 1 for activate SceneAnimation, 0 for deactivate SceneAnimation.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state);

   /**
     * @brief Register getFormRect proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister get form rect proxy in fms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterGetFormRectProxy();

    /**
     * @brief Get the form rect.
     * @param formId The formId.
     * @param rect The desktop's rect related to the specified formId.
     * @return Returns error code of method execute, which ERR_OK represents success.
     */
    ErrCode GetFormRect(const int64_t formId, Rect &rect);

    /**
     * @brief Register getLiveFormStatus proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Unregister get live form status proxy in fms
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterGetLiveFormStatusProxy();

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect);

    /**
    * @brief Reload specified forms of application.
    * @param reloadNum The number of forms to be updated.
    * @param moduleName The name of the application module to which this form belongs.
    * @param abilityName The class name of the ability to which this form belongs.
    * @param formName The name of this form.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode ReloadForms(int32_t &reloadNum, const std::string &moduleName, const std::string &abilityName,
        const std::string &formName);

    /**
     * @brief Reload all forms of application.
     * @param reloadNum The number of forms to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ReloadAllForms(int32_t &reloadNum);

    /**
     * @brief Check form is due control.
     * @param formMajorInfo form major info.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @return Returns true for form is due controlled.
     */
    bool IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy);
private:
    /**
     * @brief Connect form manager service.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode Connect();

    /**
    * @brief Reconnect form manager service once per 1000 milliseconds,
    *        until the connection succeeds or reaching the max retry times.
    * @return Returns true if execute success, false otherwise.
    */
    bool Reconnect();
    /**
     * @brief Reset proxy.
     * @param remote remote object.
     */
    void ResetProxy(const wptr<IRemoteObject> &remote);

    /**
     * @brief Check the validity of the remote proxy.
     * @return Returns true if the remote proxy is valid.
     */
    bool IsRemoteProxyValid();

    /**
     * @class FormMgrDeathRecipient
     * FormMgrDeathRecipient notices IRemoteBroker died.
     */
    class FormMgrDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        FormMgrDeathRecipient() = default;
        ~FormMgrDeathRecipient() = default;

        /**
         * @brief Notices IRemoteBroker died.
         * @param remote remote object.
         */
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        DISALLOW_COPY_AND_MOVE(FormMgrDeathRecipient);
    };

    // Shared locks are used here, write locks are used for setting remoteProxy_ operations,
    // and concurrent read locks are used for reading remoteProxy_ operations.
    std::shared_mutex connectMutex_;
    sptr<IFormMgr> remoteProxy_;

    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};

    // True: need to get a new fms remote object,
    // False: no need to get a new fms remote object.
    volatile bool resetFlag_ = false;

    static std::atomic<int> recoverStatus_;

    std::vector<std::shared_ptr<FormCallbackInterface>> formDeathCallbacks_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_H
