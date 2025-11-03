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

#ifndef OHOS_FORM_FWK_FORM_MGR_INTERFACE_H
#define OHOS_FORM_FWK_FORM_MGR_INTERFACE_H

#include <vector>
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_js_info.h"
#include "form_provider_data.h"
#include "form_provider_data_proxy.h"
#include "form_share_info.h"
#include "form_state_info.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "running_form_info.h"
#include "form_lock_info.h"
#include "form_major_info.h"

#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;

/**
 * @class IFormMgr
 * IFormMgr interface is used to access form manager service.
 */
class IFormMgr : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormMgr")

    /**
     * @brief Add form with want, send want to form manager service.
     * @param formId The Id of the forms to add.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo) = 0;

    /**
     * @brief Add form with want, send want to form manager service.
     * @param want The want of the form to add.
     * @param runningFormInfo Running form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CreateForm(const Want &want, RunningFormInfo &runningFormInfo)
    {
        return ERR_OK;
    };

    /**
     * @brief Delete forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to delete.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Stop rendering form.
     * @param formId The Id of the forms to delete.
     * @param compId The compId of the forms to delete.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int StopRenderingForm(const int64_t formId, const std::string &compId)
    {
        return ERR_OK;
    };

    /**
     * @brief Release forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to release.
     * @param callerToken Caller ability token.
     * @param delCache Delete Cache or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) = 0;

    /**
     * @brief Update form with formId, send formId to form manager service.
     * @param formId The Id of the form to update.
     * @param formProviderData Form binding data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int UpdateForm(const int64_t formId, const FormProviderData &formProviderData) = 0;

    /**
     * @brief Set next refresh time.
     * @param formId The Id of the form to update.
     * @param nextTime Next refresh time.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) = 0;

    /**
     * @brief Release renderer.
     * @param formId The Id of the forms to release.
     * @param compId The compId of the forms to release.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int ReleaseRenderer(int64_t formId, const std::string &compId) { return ERR_OK; }

    /**
     * @brief Request to publish a form to the form host.
     *
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried with.
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
                                       std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) = 0;

    virtual ErrCode SetPublishFormResult(const int64_t formId, Constants::PublishFormResult &errorCodeInfo)
    {
        return ERR_OK;
    }

    virtual ErrCode AcquireAddFormResult(const int64_t formId)
    {
        return ERR_OK;
    }

    /**
     * @brief Request to publish a form to the form host for normal authority.
     *
     * @param want The want of the form to publish.
     * @param withFormBindingData Indicates whether the formBindingData is carried with.
     * @param formBindingData Indicates the form data.
     * @param formId Return the form id to be published.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) = 0;

    /**
     * @brief Lifecycle update.
     * @param formIds The Id of the forms.
     * @param callerToken Caller ability token.
     * @param updateType update type, enable if true and disable if false.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
    bool updateType) = 0;

    /**
     * @brief Request form with formId and want, send formId and want to form manager service.
     * @param formId The Id of the form to request.
     * @param callerToken Caller ability token.
     * @param want The want of the form to add.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) = 0;

    /**
     * @brief Form visible/invisible notify, send formIds to form manager service.
     * @param formIds The Id list of the forms to notify.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
    const int32_t formVisibleType) = 0;

    /**
     * @brief Query whether has visible form by tokenId.
     * @param tokenId Unique identification of application.
     * @return Returns true if has visible form, false otherwise.
     */
    virtual bool HasFormVisible(const uint32_t tokenId) = 0;

    /**
     * @brief temp form to normal form.
     * @param formId The Id of the form.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Dump all of form storage infos.
     * @param formInfos All of form storage infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpStorageFormInfos(std::string &formInfos) = 0;
    /**
     * @brief Dump form info by a bundle name.
     * @param bundleName The bundle name of form provider.
     * @param formInfos Form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) = 0;
    /**
     * @brief Dump form info by a bundle name.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) = 0;
    /**
     * @brief Dump form timer by form id.
     * @param formId The id of the form.
     * @param formInfo Form timer.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) = 0;
    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Process Background event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Process js router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    virtual int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Delete the invalid forms.
     * @param formIds Indicates the ID of the valid forms.
     * @param callerToken Caller ability token.
     * @param numFormsDeleted Returns the number of the deleted forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
                                   int32_t &numFormsDeleted) = 0;

    /**
     * @brief Acquire form state info by passing a set of parameters (using Want) to the form provider.
     * @param want Indicates a set of parameters to be transparently passed to the form provider.
     * @param callerToken Caller ability token.
     * @param stateInfo Returns the form's state info of the specify.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
                                 FormStateInfo &stateInfo) = 0;

    /**
       * @brief Notify the form is visible or not.
       * @param formIds Indicates the ID of the forms.
       * @param isVisible Visible or not.
       * @param callerToken Host client.
       * @return Returns ERR_OK on success, others on failure.
       */
    virtual int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
                                   const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Notify the form is privacy protected or not.
     * @param formIds Indicates the ID of the forms.
     * @param isProtected isProtected or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
                                            const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Notify the form is enable to be updated or not.
     * @param formIds Indicates the ID of the forms.
     * @param isEnableUpdate enable update or not.
     * @param callerToken Host client.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
                                        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Get All FormsInfo.
     * @param formInfos Return the forms' information of all forms provided.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetAllFormsInfo(std::vector<FormInfo> &formInfos) = 0;

    /**
     * @brief Get forms info by bundle name .
     * @param bundleName Application name.
     * @param formInfos Return the forms' information of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) = 0;

    /**
     * @brief Get forms info by bundle name and module name.
     * @param bundleName bundle name.
     * @param moduleName Module name of hap.
     * @param formInfos Return the forms' information of the specify bundle name and module name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                                     std::vector<FormInfo> &formInfos) = 0;

    /**
     * @brief Get forms info specfied by filter parameters.
     * @param filter Filter that contains necessary conditions, such as bundle name, module name, dimensions.
     * @param formInfos Return the forms' information specified by filter.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetFormsInfoByFilter(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos)
    {
        return ERR_OK;
    }

    /**
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved by form service manager.
    * @param filter Filter that contains attributes that the formInfos have to have.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) = 0;

    /**
    * @brief This function is called by formProvider and gets forms info by formId of the calling ability.
    *        The conditions will be retrieved by form service manager.
    * @param formId
    * @param formInfo Return the forms' information
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo)
    {
        return 0;
    }

    /**
    * @brief This function is called by formProvider and gets forms info.
    * @param formInfos Return the forms' information
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos)
    {
        return 0;
    }

    /**
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    virtual bool IsRequestPublishFormSupported() = 0;

    /**
     * @brief Start an ability. This function can only be called by a form extension of a system app.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @param callerToken token of the ability that initially calls this function.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Start an ability by form manager service.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartAbilityByFms(const Want &want)
    {
        return 0;
    }

    /**
     * @brief Start an ability by cross bundle.
     * @param want includes ability name, parameters and related info sending to an ability.
     * @return Returns ERR_OK on success, others on failure.
     */
     virtual int32_t StartAbilityByCrossBundle(const Want &want)
     {
         return 0;
     }

    /**
     * @brief Share form by formID and deviceID.
     * @param formId Indicates the unique id of form.
     * @param deviceId Indicates the remote device ID.
     * @param callerToken Host client.
     * @param requestCode Indicates the request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
        int64_t requestCode) = 0;

    /**
     * @brief Acquire form data by formId.
     * @param formId The Id of the form to acquire data.
     * @param requestCode The request code of this form.
     * @param callerToken Indicates the host client.
     * @param formData Return the forms' information of customization
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
         AAFwk::WantParams &formData) = 0;

    /**
     * @brief Receive form sharing information from remote.
     * @param info Indicates form sharing information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) = 0;

    /**
    * @brief Check form manager service ready.
    * @return Returns ERR_OK if form manager service Ready, other values otherwise.
    */
    virtual int32_t CheckFMSReady() = 0;

    /**
     * @brief Check whether the form is system app.
     * @param bundleName The bundleName of the form.
     * @return Returns true if the form app is system, others false.
     */
    virtual bool IsSystemAppForm(const std::string &bundleName)
    {
        return false;
    }

    /**
     * @brief Register form add observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterFormAddObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Register form remove observer by bundle.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief The Call Event triggers the callee method.
     * @param funcName function name which is used by callee.
     * @param params parameter which is used by callee.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetBackgroundFunction(const std::string funcName, const std::string params) = 0;
    /**
    * @brief get forms count.
    * @param isTempFormFlag Indicates temp form or not.
    * @param formCount Returns the number of the cast or temp form.
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount) = 0;

    /**
    * @brief get host forms count.
    * @param bundleName Indicates form host bundleName.
    * @param formCount Returns the number of the host form.
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount) = 0;

    /**
     * @brief Get the running form infos.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos currently.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) = 0;

    /**
     * @brief Get the running form infos by bundle name.
     * @param bundleName Application name.
     * @param isUnusedIncluded Indicates whether to include unused forms.
     * @param runningFormInfos Return the running forms' infos of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) = 0;

    /**
    * @brief Get form instances by filter info.
    * @param formInstancesFilter includes bundleName, moduleName, formName, abilityName to get formInstances.
    * @param formInstances return formInstances
    * @return return ERR_OK on get info success, others on failure.
    */
    virtual ErrCode GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances) = 0;

   /**
    * @brief Get form instance by formId.
    * @param formId formId Indicates the unique id of form.
    * @param formInstance return formInstance
    * @return return ERR_OK on get info success, others on failure.
    */
    virtual ErrCode GetFormInstanceById(const int64_t formId, FormInstance &formInstance) = 0;

    /**
     * @brief Get form instance by formId, include form store in DB.
     * @param formId formId Indicates the unique id of form.
     * @param isUnusedIncluded Indicates whether to include unused form instance.
     * @param formInstance return formInstance
     * @return return ERR_OK on get info success, others on failure.
     */
    virtual ErrCode GetFormInstanceById(const int64_t formId, bool isUnusedIncluded, FormInstance &formInstance)
    {
        return 0;
    }

    /**
     * @brief Register form add observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Register form remove observer.
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Register form router event proxy.
     * @param formIds Indicates the id of the forms.
     * @param callerToken Router proxy call back client.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken) = 0;

    /**
     * @brief Unregister form router event proxy.
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds) = 0;

    /**
     * @brief Update proxy form with formId.
     * @param formId The Id of the form to update.
     * @param FormProviderData Form binding data.
     * @param std::vector<FormDataProxy> Form proxy vector.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateProxyForm(int64_t formId, const FormProviderData &FormProviderData,
        const std::vector<FormDataProxy> &formDataProxies) { return ERR_OK; }

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
        const std::vector<FormDataProxy> &formDataProxies) { return ERR_OK; }

    /**
     * @brief Registers the callback to publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
    {
        return 0;
    }

    /**
     * @brief Unregisters the callback to publish form. The callback is used to process the publish form request
     * when the system handler is not found.
     * @param interceptorCallback The injected callback, should implementation IFormPublishInterceptor.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback)
    {
        return 0;
    }

    /**
     * @brief Register click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) = 0;

    /**
     * @brief Unregister click callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param observer Form click event callback listener.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) = 0;

    /**
     * @brief Set forms recyclable
     * @param formIds Indicates the id of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetFormsRecyclable(const std::vector<int64_t> &formIds)
    {
        return 0;
    }

    /**
     * @brief Recycle forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recycled.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RecycleForms(const std::vector<int64_t> &formIds, const Want &want)
    {
        return 0;
    }

    /**
     * @brief Recover recycled forms
     * @param formIds Indicates the id of the forms.
     * @param want The want of forms to be recovered.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RecoverForms(const std::vector<int64_t> &formIds, const Want &want)
    {
        return 0;
    }

    /**
     * @brief Update formLocation with formId.
     * @param formId The Id of the form to update.
     * @param formLocation The FormLocation.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateFormLocation(const int64_t &formId, const int32_t &formLocation)
    {
        return ERR_OK;
    }

    /**
     * @brief Update form with formRefreshType, send to form manager service.
     * @param formRefreshType The type of the form to refresh, 0: AllForm 1: 2: AppForm 2: AtomicServiceForm
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t BatchRefreshForms(const int32_t formRefreshType)
    {
        return 0;
    }

    /**
     * @brief enable/disable form update.
     * @param bundleName BundleName of the form host.
     * @param enable True for enable form, false for disable form.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t EnableForms(const std::string bundleName, const int32_t userId, const bool enable)
    {
        return 0;
    }

    /**
     * @brief Check form bundle is controlled.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle is controlled.
     */
    virtual bool IsFormBundleForbidden(const std::string &bundleName)
    {
        return false;
    }

    /**
     * @brief lock/unlock form update.
     * @param formLockInfos Indicates the lockForm data.
     * @param type Indicates the Lock Type.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t LockForms(const std::vector<FormLockInfo> &formLockInfos, OHOS::AppExecFwk::LockChangeType type)
    {
        return 0;
    }

    /**
     * @brief Check form bundle is protect.
     * @param bundleName The bundle name of form to be check.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is protect.
     */
    virtual bool IsFormBundleProtected(const std::string &bundleName, int64_t formId)
    {
        return false;
    }
    
    /**
     * @brief Check form bundle signature is debug.
     * @param bundleName The bundle name of form to be check.
     * @return Returns true for form bundle signature is debug.
     */
    virtual bool IsFormBundleDebugSignature(const std::string &bundleName)
    {
        return false;
    }

    /**
     * @brief Check form bundle is exempt.
     * @param formId The Id of the form to query.
     * @return Returns true for form bundle is exempt.
     */
    virtual bool IsFormBundleExempt(int64_t formId)
    {
        return false;
    }

    /**
     * @brief Notify the form is locked or not.
     * @param formId Indicates the ID of the form.
     * @param isLocked locked or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t NotifyFormLocked(const int64_t &formId, bool isLocked)
    {
        return 0;
    }

    /**
     * @brief Update size of form.
     * @param formId The Id of the form to update.
     * @param width The width value to be updated.
     * @param height The height value to be updated.
     * @param borderWidth The borderWidth value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth)
    {
        return ERR_OK;
    }

    /**
     * @brief Open the form edit ability.
     * @param abilityName The form edit ability name.
     * @param formId The edit form ID.
     * @param isMainPage Open the main edit page.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage)
    {
        return ERR_OK;
    }

    /**
     * @brief Register overflow proxy in fms
     * @param callerToken The form host proxy
     * @return Return true for form register success
     */
    virtual bool RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken)
    {
        return false;
    }

    /**
     * @brief Unregister overflow proxy in fms
     * @return Return true for form unregister success
     */
    virtual bool UnregisterOverflowProxy()
    {
        return false;
    }

    /**
     * @brief Request overflow with specific range
     * @param formId The id of the form to request overflow
     * @param overflowInfo The overflowInfo to explict overflow area and duration
     * @param isOverflow True for request overflow, false for cancel overflow, default value is true
     * @return Return ERR_OK on success, others on failure
     */
    virtual ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow = true)
    {
        return ERR_OK;
    }

    /**
     * @brief Register change sceneAnimation state proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns true for change SceneAnimation state proxy register success.
     */
    virtual bool RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken)
    {
        return false;
    }

    /**
     * @brief Unregister change sceneAnimation state proxy in fms.
     * @return Returns true for change SceneAnimation state proxy unregister success.
     */
    virtual bool UnregisterChangeSceneAnimationStateProxy()
    {
        return false;
    }

    /**
     * @brief Change SceneAnimation State.
     * @param formId The formId.
     * @param state 1 for activate SceneAnimation, 0 for deactivate SceneAnimation
     * @return Return ERR_OK on success, others on failure
     */
    virtual ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state)
    {
        return ERR_OK;
    }

    /**
     * @brief Set get form rect proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns ERR_OK for setting success.
     */
    virtual bool RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken)
    {
        return false;
    }

    /**
     * @brief Unregister get form rect proxy in fms.
     * @return Returns true for get form rect proxy unregister success.
     */
    virtual bool UnregisterGetFormRectProxy()
    {
        return false;
    }
 
    /**
     * @brief Get the form rect.
     * @param formId The formId.
     * @param rect The desktop's rect related to the specified formId.
     * @return Returns error code of method execute, which ERR_OK represents success.
     */
    virtual ErrCode GetFormRect(const int64_t formId, Rect &rect)
    {
        return ERR_OK;
    }

    /**
     * @brief Update form size.
     * @param formId The Id of the form to update.
     * @param newDimension The dimension value to be updated.
     * @param newRect The rect value to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode UpdateFormSize(const int64_t formId, const int32_t newDimension, const Rect &newRect)
    {
        return ERR_OK;
    }

    /**
     * @brief Set get live form status proxy in fms.
     * @param callerToken The form host proxy.
     * @return Returns true for get live form status proxy register success.
     */
    virtual bool RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken)
    {
        return false;
    }
 
    /**
     * @brief Unregister get live form status proxy in fms.
     * @return Returns true for get live form status proxy unregister success.
     */
    virtual bool UnregisterGetLiveFormStatusProxy()
    {
        return false;
    }

    /**
    * @brief Reload specified forms of application.
    * @param reloadNum The number of forms to be updated.
    * @param moduleName The name of the application module to which this form belongs.
    * @param abilityName The class name of the ability to which this form belongs.
    * @param formName The name of this form.
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual ErrCode ReloadForms(int32_t &reloadNum, const std::string &moduleName, const std::string &abilityName,
        const std::string &formName)
    {
        return ERR_OK;
    }

    /**
     * @brief Reload all forms of application.
     * @param reloadNum The number of forms to be updated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual ErrCode ReloadAllForms(int32_t &reloadNum)
    {
        return ERR_OK;
    }

    /**
     * @brief Check form is due control.
     * @param formMajorInfo form major info.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @return Returns true for form is due disabled.
     */
    virtual bool IsFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy)
    {
        return false;
    }

    enum class Message {
        // ipc id 1-1000 for kit
        // ipc id 1001-2000 for DMS
        // ipc id 2001-3000 for tools
        // ipc id for create (3001)
        FORM_MGR_ADD_FORM = 3001,
        FORM_MGR_ADD_FORM_OHOS,
        FORM_MGR_DELETE_FORM,
        FORM_MGR_UPDATE_FORM,
        FORM_MGR_LIFECYCLE_UPDATE,
        FORM_MGR_REQUEST_FORM,
        FORM_MGR_RELEASE_FORM,
        FORM_MGR_RELEASE_CACHED_FORM,
        FORM_MGR_CAST_TEMP_FORM,
        FORM_MGR_EVENT_NOTIFY,
        FORM_MGR_CHECK_AND_DELETE_INVALID_FORMS,
        FORM_MGR_SET_NEXT_REFRESH_TIME,
        FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE,
        FORM_MGR_STORAGE_FORM_INFOS,
        FORM_MGR_FORM_INFOS_BY_NAME,
        FORM_MGR_FORM_INFOS_BY_ID,
        FORM_MGR_FORM_TIMER_INFO_BY_ID,
        FORM_MGR_MESSAGE_EVENT,
        FORM_MGR_BATCH_ADD_FORM_RECORDS_ST,
        FORM_MGR_CLEAR_FORM_RECORDS_ST,
        FORM_MGR_DISTRIBUTED_DATA_ADD_FORM__ST,
        FORM_MGR_DISTRIBUTED_DATA_DELETE_FORM__ST,
        FORM_MGR_DELETE_INVALID_FORMS,
        FORM_MGR_ACQUIRE_FORM_STATE,
        FORM_MGR_NOTIFY_FORMS_VISIBLE,
        FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE,
        FORM_MGR_GET_ALL_FORMS_INFO,
        FORM_MGR_GET_FORMS_INFO_BY_APP,
        FORM_MGR_GET_FORMS_INFO_BY_MODULE,
        FORM_MGR_GET_FORMS_INFO,
        FORM_MGR_ROUTER_EVENT,
        FORM_MGR_UPDATE_ROUTER_ACTION,
        FORM_MGR_ADD_FORM_INFO,
        FORM_MGR_REMOVE_FORM_INFO,
        FORM_MGR_REQUEST_PUBLISH_FORM,
        FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED,
        FORM_MGR_SHARE_FORM,
        FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE,
        FORM_MGR_START_ABILITY,
        FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED,
        FORM_MGR_CHECK_FMS_READY,
        FORM_MGR_BACKGROUND_EVENT,
        FORM_MGR_STOP_RENDERING_FORM,
        FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE,
        FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE,
        FORM_MGR_ACQUIRE_DATA,
        FORM_MGR_GET_FORMS_COUNT,
        FORM_MGR_GET_HOST_FORMS_COUNT,
        FORM_MGR_GET_RUNNING_FORM_INFOS,
        FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE,
        FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER,
        FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID,
        FORM_MGR_REGISTER_ADD_OBSERVER,
        FORM_MGR_REGISTER_REMOVE_OBSERVER,
        FORM_MGR_UPDATE_PROXY_FORM,
        FORM_MGR_REQUEST_PUBLISH_PROXY_FORM,
        FORM_MGR_RELEASE_RENDERER,
        FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR,
        FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR,
        FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER,
        FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER,
        FORM_MGR_REGISTER_FORM_ROUTER_PROXY,
        FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY,
        FORM_MGR_SET_FORMS_RECYCLABLE,
        FORM_MGR_RECYCLE_FORMS,
        FORM_MGR_RECOVER_FORMS,
        FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID,
        FORM_MGR_UPDATE_FORM_LOCATION,
        FORM_MGR_GET_FORMS_INFO_BY_FILTER,
        FORM_MGR_CREATE_FORM,
        FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT,
        FORM_MGR_ACQUIRE_ADD_FORM_RESULT,
        FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT,
        FORM_MGR_BATCH_REFRESH_FORMS,
        FORM_MGR_ENABLE_FORMS,
        FORM_MGR_IS_SYSTEM_APP_FORM,
        FORM_MGR_IS_FORM_BUNDLE_FORBIDDEN,
        FORM_MGR_UPDATE_FORM_SIZE,
        FORM_MGR_LOCK_FORMS,
        FORM_MGR_IS_FORM_BUNDLE_PEOTECTED,
        FORM_MGR_IS_FORM_BUNDLE_EXEMPT,
        FORM_MGR_NOTIFY_FORM_LOCKED,
        FORM_MGR_START_ABILITY_BY_FMS,
        FORM_MGR_START_ABILITY_BY_CROSS_BUNDLE,
        FORM_MGR_GET_PUBLISHED_FORM_INFOS,
        FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID,
        FORM_MGR_OPEN_FORM_EDIT_ABILITY,
        FORM_MGR_REGISTER_OVERFLOW_PROXY,
        FORM_MGR_UNREGISTER_OVERFLOW_PROXY,
        FORM_MGR_REQUEST_OVERFLOW,
        FORM_MGR_REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        FORM_MGR_UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        FORM_MGR_CHANGE_SCENE_ANIMATION_STATE,
        FORM_MGR_REGISTER_GET_FORM_RECT,
        FORM_MGR_UNREGISTER_GET_FORM_RECT,
        FORM_MGR_GET_FORM_RECT,
        FORM_MGR_NOTIFY_UPDATE_FORM_SIZE,
        FORM_MGR_REGISTER_GET_LIVE_FORM_STATUS,
        FORM_MGR_UNREGISTER_GET_LIVE_FORM_STATUS,
        FORM_MGR_IS_FORM_BUNDLE_DEBUG_SIGNATURE,
        FORM_MGR_RELOAD_FORMS,
        FORM_MGR_RELOAD_ALL_FORMS,
        FORM_MGR_IS_FORM_DUE_CONTROL,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_INTERFACE_H
