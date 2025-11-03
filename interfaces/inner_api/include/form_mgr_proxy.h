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

#ifndef OHOS_FORM_FWK_FORM_MGR_PROXY_H
#define OHOS_FORM_FWK_FORM_MGR_PROXY_H

#include "data_center/database/form_db_info.h"
#include "form_info.h"
#include "form_mgr_interface.h"
#include "form_state_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "running_form_info.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormMgrProxy
 * FormMgrProxy is used to access form manager service.
 */
class FormMgrProxy : public IRemoteProxy<IFormMgr> {
public:
    explicit FormMgrProxy(const sptr<IRemoteObject> &impl);
    virtual ~FormMgrProxy() = default;
    /**
     * @brief Add form with want, send want to form manager service.
     * @param formId The Id of the forms to add.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
        FormJsInfo &formInfo) override;

    /**
     * @brief Add form with want, send want to form manager service.
     * @param want The want of the form to add.
     * @param runningFormInfo Running form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CreateForm(const Want &want, RunningFormInfo &runningFormInfo) override;

    /**
     * @brief Delete forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to delete.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Stop rendering form.
     * @param formId The Id of the forms to delete.
     * @param compId The compId of the forms to delete.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int StopRenderingForm(const int64_t formId, const std::string &compId) override;

     /**
     * @brief Release forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to release.
     * @param callerToken Caller ability token.
     * @param delCache Delete Cache or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override;

    /**
     * @brief Update form with formId, send formId to form manager service.
     * @param formId The Id of the form to update.
     * @param FormProviderData Form binding data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int UpdateForm(const int64_t formId, const FormProviderData &FormProviderData) override;

    /**
     * @brief Set next refresh time.
     * @param formId The Id of the form to update.
     * @param nextTime Next refresh time.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override;

    /**
     * @brief Release renderer.
     * @param formId The Id of the forms to release.
     * @param compId The compId of the forms to release.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int ReleaseRenderer(int64_t formId, const std::string &compId) override;

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
                               std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override;

    ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo) override;

    ErrCode AcquireAddFormResult(const int64_t formId) override;
    /**
     * @brief Lifecycle update.
     * @param formIds The Id of the forms.
     * @param callerToken Caller ability token.
     * @param updateType update type, enable if true and disable if false.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
    bool updateType) override;

    /**
     * @brief Request form with formId and want, send formId and want to form manager service.
     * @param formId The Id of the form to update.
     * @param callerToken Caller ability token.
     * @param want The want of the form to add.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override;

    /**
     * @brief Form visible/invisible notify, send formIds to form manager service.
     * @param formIds The Id list of the forms to notify.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
    const int32_t formVisibleType) override;

    /**
     * @brief Query whether has visible form by tokenId.
     * @param tokenId Unique identification of application.
     * @return Returns true if has visible form, false otherwise.
     */
    virtual bool HasFormVisible(const uint32_t tokenId) override;

    /**
     * @brief temp form to normal form.
     * @param formId The Id of the form.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Dump all of form storage infos.
     * @param formInfos All of form storage infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpStorageFormInfos(std::string &formInfos) override;
    /**
     * @brief Dump form info by a bundle name.
     * @param bundleName The bundle name of form provider.
     * @param formInfos Form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override;
    /**
     * @brief Dump form info by a bundle name.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override;
    /**
     * @brief Dump timer info by form id.
     * @param formId The id of the form.
     * @param formInfo Form timer info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override;
    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Process js router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Process Background event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Delete the invalid forms.
     * @param formIds Indicates the ID of the valid forms.
     * @param callerToken Caller ability token.
     * @param numFormsDeleted Returns the number of the deleted forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                   int32_t &numFormsDeleted) override;

    /**
     * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
     * @param want Indicates a set of parameters to be transparently passed to the form provider.
     * @param callerToken Caller ability token.
     * @param stateInfo Returns the form's state info of the specify.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
                                 FormStateInfo &stateInfo) override;

    /**
     * @brief Notify the form is visible or not.
     * @param formIds Indicates the ID of the forms.
     * @param isVisible Visible or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                   const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify the form is privacy protected or not.
     * @param formIds Indicates the ID of the forms.
     * @param isProtected isProtected or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                            const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify the form is enable to be updated or not.
     * @param formIds Indicates the ID of the forms.
     * @param isEnableUpdate enable update or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Get All FormsInfo.
     * @param formInfos Return the forms' information of all forms provided.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetAllFormsInfo(std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Get forms info by bundle name .
     * @param bundleName Application name.
     * @param formInfos Return the forms' information of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Get forms info by bundle name and module name.
     * @param bundleName bundle name.
     * @param moduleName Module name of hap.
     * @param formInfos Return the forms' information of the specify bundle name and module name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                                     std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Get forms info specfied by filter parameters.
     * @param filter Filter that contains necessary conditions, such as bundle name, module name, dimensions.
     * @param formInfos Return the forms' information specified by filter.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override;

    /**
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved by form service manager.
    * @param filter Filter that contains attributes that the formInfos have to have.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override;

    /**
     * @brief This function is called by formProvider and gets forms info by the formId of the calling ability.
     *        The formId will be retrieved by form service manager.
     * @param formId
     * @param formInfo Return the form' information of the calling formId
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo) override;

    /**
    * @brief This function is called by formProvider and gets forms info.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos) override;

    /**
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    bool IsRequestPublishFormSupported() override;

    /**
     * @brief Start an ability. This function can only be called by a form extension of a system app.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @param callerToken token of the ability that initially calls this function.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Start an ability by form manager service.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbilityByFms(const Want &want) override;

    /**
     * @brief Start an ability by cross bundle.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbilityByCrossBundle(const Want &want) override;

    /**
     * @brief Share form by formID and deviceID.
     * @param formId Indicates the unique id of form.
     * @param deviceId Indicates the remote device ID.
     * @param callerToken Host client.
     * @param requestCode the request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
        int64_t requestCode) override;

    /**
     * @brief Acquire form data by formId.
     * @param formId The Id of the form to acquire data.
     * @param requestCode The request code of this form.
     * @param callerToken Indicates the host client.
     * @param formData Return the forms' information of customization
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData) override;

    /**
     * @brief Receive form sharing information from remote.
     * @param info Indicates form sharing information.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override;

    /**
    * @brief Check form manager service ready.
    * @return Returns ERR_OK if form manager service Ready, other values otherwise.
    */
    int32_t CheckFMSReady() override;

    /**
     * @brief Check whether the form is system app.
     * @param bundleName The bundleName of the form.
     * @return Returns true if the form app is system, others false.
     */
    bool IsSystemAppForm(const std::string &bundleName) override;

    /**
     * @brief Register form add observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormAddObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Register form remove observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief The Call Event triggers the callee method.
     * @param funcName function name which is used by callee.
     * @param params parameter which is used by callee.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetBackgroundFunction(const std::string funcName, const std::string params) override;

    /**
    * @brief get forms count.
    * @param isTempFormFlag Indicates temp form or not.
    * @param formCount Returns the number of the cast or temp form.
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount) override;

    /**
    * @brief get host forms count.
    * @param bundleName Indicates form host bundleName.
    * @param formCount Returns the number of the host form.
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount) override;

    /**
     * @brief Get the running form infos.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos currently.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override;

    /**
     * @brief Get the running form infos by bundle name.
     * @param bundleName Application name.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override;

    /**
     * @brief Get form instances by filter info.
     * @param formInstancesFilter includes bundleName, moduleName, formName, abilityName to get formInstances.
     * @param formInstances return formInstances
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances) override;

   /**
    * @brief Get form instance by formId.
    * @param formId formId Indicates the unique id of form.
    * @param formInstance return formInstance
    * @return return ERR_OK on get info success, others on failure.
    */
    ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstance) override;

    /**
     * @brief Get form instance by formId, include form store in DB.
     * @param formId formId Indicates the unique id of form.
     * @param isUnusedIncluded Indicates whether to include unused form.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance) override;

    /**
     * @brief Register form add observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Register form remove observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Register form router event proxy.
     * @param formIds Indicates the id of the forms.
     * @param callerToken Router proxy call back client.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Unregister form router event proxy.
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds) override;

    /**
     * @brief Update proxy form with formId, send formId to form manager service.
     * @param formId The Id of the form to update.
     * @param FormProviderData Form binding data.
     * @param std::vector<FormDataProxy> Form proxy vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateProxyForm(int64_t formId, const FormProviderData &FormProviderData,
        const std::vector<FormDataProxy> &formDataProxies) override;

    /**
     * @brief Request to publish a proxy form to the form host.
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried with.
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @param std::vector<FormDataProxy> Form proxy vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RequestPublishProxyForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
        const std::vector<FormDataProxy> &formDataProxies) override;

    /**
     * @brief Registers the callback to publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback) override;

    /**
     * @brief Unregisters the callback to publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback) override;

    /**
     * @brief Register click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override;

    /**
     * @brief Unregister click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override;

    /**
     * @brief Set forms recyclable
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds) override;

    /**
     * @brief Recycle forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recycled.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want) override;

    /**
     * @brief Recover recycled forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recovered.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want) override;

    /**
     * @brief Update formLocation with formId.
     * @param formId The Id of the form to update.
     * @param formLocation The FormLocation.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation) override;

    /**
     * @brief Request to publish a form to the form host with normal authority.
     *
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried wit
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override;

    /**
     * @brief Update form with formRefreshType, send to form manager service.
     * @param formRefreshType The type of the form to refresh, 0: AllForm 1: 2: AppForm 2: AtomicServiceForm
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t BatchRefreshForms(const int32_t formRefreshType) override;

    /**
     * @brief enable/disable form update.
     * @param bundleName BundleName of the form host.
     * @param enable True for enable form, false for disable form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t EnableForms(const std::string bundleName, const int32_t userId, const bool enable) override;

    /**
     * @brief Check form bundle is controlled.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle is controlled.
     */
    bool IsFormBundleForbidden(const std::string &bundleName) override;

    /**
     * @brief lock/unlock form update.
     * @param formLockInfos Indicates the lockForm data.
     * @param type Indicates the Lock Type.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t LockForms(const std::vector<FormLockInfo> &formLockInfos, OHOS::AppExecFwk::LockChangeType type) override;

    /**
     * @brief Check form bundle is protect.
     * @param bundleName The bundle name of form to be check.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is protect.
     */
    bool IsFormBundleProtected(const std::string &bundleName, int64_t formId) override;

    /**
     * @brief Check form bundle signature is debug.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle signature is debug.
     */
    bool IsFormBundleDebugSignature(const std::string &bundleName) override;

    /**
     * @brief Check form bundle is exempt.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is exempt.
     */
    bool IsFormBundleExempt(int64_t formId = 0) override;

    /**
     * @brief Notify the form is locked or not.
     * @param formId Indicates the ID of the form.
     * @param isLocked locked or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t NotifyFormLocked(const int64_t &formId, bool isLocked) override;

    /**
     * @brief Update size of form.
     * @param formId The Id of the form to update.
     * @param width The width value to be updated.
     * @param height The height value to be updated.
     * @param borderWidth The borderWidth value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth) override;

    /**
     * @brief Open the form edit ability.
     * @param abilityName The form edit ability name.
     * @param formId The edit form ID.
     * @param isMainPage Open the main edit page.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage) override;

    /**
     * @brief Register overflow proxy in fms
     * @param callerToken The form host proxy
     * @return Return true for form register success
     */
    bool RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Unregister overflow proxy in fms
     * @return Return true if unregister success
     */
    bool UnregisterOverflowProxy() override;

    /**
     * @brief Request overflow with specific range
     * @param formId The id of the form to request overflow
     * @param overflowInfo The overflowInfo to explict overflow area and duration
     * @param isOverflow True for request overflow, false for cancel overflow, default value is true
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow = true) override;

    /**
     * @brief Register change sceneAnimation state proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns true for change sceneAnimation state proxy register success.
     */
    bool RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Unregister change sceneAnimation state proxy in fms.
     * @return Returns true for change sceneAnimation state proxy unregister success.
     */
    bool UnregisterChangeSceneAnimationStateProxy() override;

    /**
     * @brief Change SceneAnimation State.
     * @param formId The formId.
     * @param state 1 for activate SceneAnimation, 2 for deactivate SceneAnimation
     * @return Return ERR_OK on success, others on failure
     */
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state) override;

    /**
     * @brief Register get form rect proxy in fms.
     * @param callerToken The form host proxy.
     * @return Return true for register success.
     */
    bool RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Unregister get form rect proxy in fms.
     * @return Return true if unregister success.
     */
    bool UnregisterGetFormRectProxy() override;
 
    /**
     * @brief Get the form rect.
     * @param formId The formId.
     * @param rect The desktop's rect related to the specified formId.
     * @return Returns error code of method execute, which ERR_OK represents success.
     */
    ErrCode GetFormRect(const int64_t formId, Rect &rect) override;

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect) override;

    /**
     * @brief Register get live form status proxy in fms.
     * @param callerToken The form host proxy.
     * @return Return true for register success.
     */
    bool RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken) override;
 
    /**
     * @brief Unregister get live form status proxy in fms.
     * @return Return true for unregister success.
     */
    bool UnregisterGetLiveFormStatusProxy() override;

    /**
    * @brief Reload specified forms of application.
    * @param reloadNum The number of forms to be updated.
    * @param moduleName The name of the application module to which this form belongs.
    * @param abilityName The class name of the ability to which this form belongs.
    * @param formName The name of this form.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode ReloadForms(int32_t &reloadNum, const std::string &moduleName, const std::string &abilityName,
        const std::string &formName) override;

    /**
     * @brief Reload all forms of application.
     * @param reloadNum The number of forms to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ReloadAllForms(int32_t &reloadNum) override;

    /**
     * @brief Check form is due control.
     * @param formMajorInfo form major info.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @return Returns true for form is due disabled.
     */
    bool IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy) override;
private:
    template<typename T>
    int GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);
    bool WriteInterfaceToken(MessageParcel &data);
    template<typename T>
    int GetParcelableInfo(IFormMgr::Message code, MessageParcel &data, T &parcelableInfo);
    int SendTransactCmd(IFormMgr::Message code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    int GetStringInfo(IFormMgr::Message code, MessageParcel &data, std::string &stringInfo);
    int32_t GetFormsInfo(IFormMgr::Message code, MessageParcel &data, std::vector<FormInfo> &formInfos);
    int32_t GetPublishedFormInfoById(IFormMgr::Message code, MessageParcel &data, RunningFormInfo &formInfo);
    int32_t GetPublishedFormInfos(IFormMgr::Message code, MessageParcel &data, std::vector<RunningFormInfo> &formInfos);
    ErrCode GetRunningFormInfos(IFormMgr::Message code, MessageParcel &data,
        std::vector<RunningFormInfo> &runningFormInfos);
    int32_t GetFormInstance(IFormMgr::Message code, MessageParcel &data, std::vector<FormInstance> &formInstances);
    bool WriteFormDataProxies(MessageParcel &data, const std::vector<FormDataProxy> &formDataProxies);
private:
    static inline BrokerDelegator<FormMgrProxy> delegator_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_PROXY_H
