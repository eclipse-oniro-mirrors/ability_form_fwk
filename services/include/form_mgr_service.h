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

#ifndef OHOS_FORM_FWK_FORM_MGR_SERVICE_H
#define OHOS_FORM_FWK_FORM_MGR_SERVICE_H

#include <singleton.h>
#include <system_ability.h>

#include "form_bundle_event_callback.h"
#include "form_event_handler.h"
#include "form_mgr_stub.h"
#include "form_provider_data.h"
#include "form_sys_event_receiver.h"
#include "iremote_object.h"
namespace OHOS {
namespace AppExecFwk {
enum class ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING,
};
/**
 * @class FormMgrService
 * FormMgrService provides a facility for managing form life cycle.
 */
class FormMgrService : public SystemAbility,
                       public FormMgrStub,
                       public std::enable_shared_from_this<FormMgrService> {
    DECLARE_DELAYED_SINGLETON(FormMgrService);
    DECLEAR_SYSTEM_ABILITY(FormMgrService);
public:
    /**
     * @brief Start event for the form manager service.
     */
    void OnStart() override;
    /**
     * @brief Stop event for the form manager service.
     */
    void OnStop() override;

    /**
     * @brief Add form with want, send want to form manager service.
     * @param formId The Id of the forms to add.
     * @param want The want of the form to add.
     * @param callerToken Caller ability token.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
        FormJsInfo &formInfo) override;

    /**
     * @brief Delete forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to delete.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Stop rendering form.
     * @param formId The Id of the forms to delete.
     * @param compId The compId of the forms to delete.
     * @return Returns ERR_OK on success, others on failure.
     */
    int StopRenderingForm(const int64_t formId, const std::string &compId) override;

    /**
     * @brief Release forms with formIds, send formIds to form manager service.
     * @param formId The Id of the forms to release.
     * @param callerToken Caller ability token.
     * @param delCache Delete Cache or not.
     * @return Returns ERR_OK on success, others on failure.
     */
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override;

    /**
     * @brief Update form with formId, send formId to form manager service.
     * @param formId The Id of the form to update.
     * @param bundleName Provider ability bundleName.
     * @param FormProviderData Form binding data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int UpdateForm(const int64_t formId, const FormProviderData &FormProviderData) override;

    /**
     * @brief set next refresh time.
     * @param formId The id of the form.
     * @param nextTime next refresh time.
     * @return Returns ERR_OK on success, others on failure.
     */
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override;

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

    /**
     * @brief lifecycle update.
     * @param formIds formIds of host client.
     * @param callerToken Caller ability token.
     * @param updateType update type, enable if true and disable if false.
     * @return Returns true on success, false on failure.
     */
    int LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        bool updateType) override;

    /**
     * @brief Request form with formId and want, send formId and want to form manager service.
     * @param formId The Id of the form to update.
     * @param callerToken Caller ability token.
     * @param want The want of the form to add.
     * @return Returns ERR_OK on success, others on failure.
     */
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override;

    /**
     * @brief Form visible/invisible notify, send formIds to form manager service.
     * @param formIds The Id list of the forms to notify.
     * @param callerToken Caller ability token.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        const int32_t formVisibleType) override;

    /**
     * @brief temp form to normal form.
     * @param formId The Id of the form.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Dump all of form storage infos.
     * @param formInfos All of form storage infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpStorageFormInfos(std::string &formInfos) override;
    /**
     * @brief Dump form info by a bundle name.
     * @param bundleName The bundle name of form provider.
     * @param formInfos Form infos.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override;
    /**
     * @brief Dump form info by a bundle name.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override;
    /**
     * @brief Dump form timer by form id.
     * @param formId The id of the form.
     * @param formInfo Form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override;
    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Process js router event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Process Background event.
     * @param formId Indicates the unique id of form.
     * @param want the want of the ability to start.
     * @param callerToken Caller ability token.
     * @return Returns true if execute success, false otherwise.
     */
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Check whether if the form manager service is ready.
     * @return Returns true if the form manager service is ready; returns false otherwise.
     */
    bool IsReady() const;

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
    int GetAllFormsInfo(std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Get forms info by bundle name .
     * @param bundleName Application name.
     * @param formInfos Return the forms' information of the specify application name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Get forms info by bundle name and module name.
     * @param bundleName bundle name.
     * @param moduleName Module name of hap.
     * @param formInfos Return the forms' information of the specify bundle name and module name.
     * @return Returns ERR_OK on success, others on failure.
     */
    int GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
                             std::vector<FormInfo> &formInfos) override;

    /**
    * @brief This function is called by formProvider and gets forms info by the bundle name of the calling ability.
    *        The bundle name will be retrieved here.
    * @param filter Filter that contains attributes that the formInfos have to have.
    * @param formInfos Return the forms' information of the calling bundle name
    * @return Returns ERR_OK on success, others on failure.
    */
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override;

    /**
     * @brief Check if the request of publishing a form is supported by the host.
     * @return Returns true if the request is supported and false otherwise.
     */
    bool IsRequestPublishFormSupported() override;

    /**
     * @brief Start an ability. This function can only be called by a form extension of a system app.
     * @param want includes ability name, parameters and relative info sending to an ability.
     * @param callerToken token of the ability that initially calls this function.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Share form by formID and deviceID.
     * @param formId Indicates the unique id of form.
     * @param deviceId Indicates the remote device ID.
     * @param callerToken Indicates the host client.
     * @param requestCode The request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t ShareForm(int64_t formId, const std::string &deviceId,
        const sptr<IRemoteObject> &callerToken, int64_t requestCode) override;

    /**
     * @brief Receive form sharing information from remote.
     * @param info Indicates form sharing information.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override;

    /**
     * @brief Dump form.
     * @param fd Indicates the file descriptor for result.
     * @param args Indicates the input arguments.
     * @return Returns ERR_OK on success, others on failure.
     */
    int Dump(int fd, const std::vector<std::u16string> &args) override;

    /**
    * @brief Check form manager service ready.
    * @return Return true if form manager service Ready; return false otherwise.
    */
    bool CheckFMSReady() override;

    /**
     * @brief The Call Event triggers the callee method.
     * @param funcName function name which is used by callee.
     * @param params parameter which is used by callee.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetBackgroundFunction(const std::string funcName, const std::string params) override
    {
        return ERR_OK;
    }
private:
    enum class DumpKey {
        KEY_DUMP_HELP = 0,
        KEY_DUMP_STORAGE,
        KEY_DUMP_BY_BUNDLE_NAME,
        KEY_DUMP_BY_FORM_ID,
    };
    /**
     * @brief initialization of form manager service.
     */
    ErrCode Init();

    ErrCode CheckFormPermission();

    void InitFormShareMgrEventHandler();

    void DumpInit();
    void Dump(const std::vector<std::u16string> &args, std::string &result);
    bool ParseOption(const std::vector<std::u16string> &args, DumpKey &key, std::string &value, std::string &result);
    void HiDumpHelp([[maybe_unused]] const std::string &args, std::string &result);
    void HiDumpStorageFormInfos([[maybe_unused]] const std::string &args, std::string &result);
    void HiDumpFormInfoByBundleName(const std::string &args, std::string &result);
    void HiDumpFormInfoByFormId(const std::string &args, std::string &result);
private:
    static const int32_t ENABLE_FORM_UPDATE = 5;
    const static std::map<std::string, DumpKey> dumpKeyMap_;
    using DumpFuncType = void (FormMgrService::*)(const std::string &args, std::string &result);
    std::map<DumpKey, DumpFuncType> dumpFuncMap_;
    ServiceRunningState state_ = ServiceRunningState::STATE_NOT_START;
    std::shared_ptr<EventRunner> runner_ = nullptr;
    std::shared_ptr<FormEventHandler> handler_ = nullptr;
    std::shared_ptr<FormSysEventReceiver> formSysEventReceiver_ = nullptr;
    sptr<FormBundleEventCallback> formBundleEventCallback_ = nullptr;
    mutable std::mutex instanceMutex_;
    DISALLOW_COPY_AND_MOVE(FormMgrService);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_MGR_SERVICE_H
