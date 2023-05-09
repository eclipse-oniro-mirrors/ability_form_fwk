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

#ifndef OHOS_FORM_FWK_FORM_MGR_INTERFACE_H
#define OHOS_FORM_FWK_FORM_MGR_INTERFACE_H

#include <vector>
#include "form_info.h"
#include "form_info_filter.h"
#include "form_js_info.h"
#include "form_provider_data.h"
#include "form_share_info.h"
#include "form_state_info.h"
#include "ipc_types.h"
#include "iremote_broker.h"

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
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved by form service manager.
    * @param filter Filter that contains attributes that the formInfos have to have.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    virtual int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) = 0;

    /**
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    virtual bool IsRequestPublishFormSupported() = 0;

    /**
     * @brief Start an ability. This function can only be called by a form extension of a system app.
     * @param want includes ability name, parameters and relative info sending to an ability.
     * @param callerToken token of the ability that initially calls this function.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) = 0;

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
     * @brief Receive form sharing information from remote.
     * @param info Indicates form sharing information.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) = 0;

    /**
    * @brief Check form manager service ready.
    * @return Return true if form manager service Ready; return false otherwise.
    */
    virtual bool CheckFMSReady() = 0;

    /**
     * @brief The Call Event triggers the callee method.
     * @param funcName function name which is used by callee.
     * @param params parameter which is used by callee.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t SetBackgroundFunction(const std::string funcName, const std::string params) = 0;

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
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_INTERFACE_H
