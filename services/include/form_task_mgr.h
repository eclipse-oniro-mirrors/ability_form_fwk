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

#ifndef OHOS_FORM_FWK_FORM_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_TASK_MGR_H

#include <singleton.h>
#include <vector>
#include <unordered_map>
#include <mutex>

#include "form_event_handler.h"
#include "form_js_info.h"
#include "form_record.h"
#include "form_serial_queue.h"
#include "form_state_info.h"
#include "iremote_object.h"
#include "running_form_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
enum class TaskType : int64_t {
    RECYCLE_FORM,
    RENDER_FORM,
};
namespace {
constexpr int32_t FORM_TASK_DELAY_TIME = 20; // ms
constexpr int32_t FORM_FRS_DIED_TASK_DELAY_TIME = 100; // ms
constexpr int32_t FORM_BUILD_DELAY_TIME = 1400; // ms
}
/**
 * @class FormTaskMgr
 * form task manager.
 */
class FormTaskMgr final : public DelayedRefSingleton<FormTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormTaskMgr)

public:
    DISALLOW_COPY_AND_MOVE(FormTaskMgr);

    /**
     * @brief SetSerialQueue.
     * @param serialQueue serial queue
     */
    inline void SetSerialQueue(const std::shared_ptr<FormSerialQueue> &serialQueue)
    {
        serialQueue_ = serialQueue;
    }

    /**
     * @brief Acquire form data from form provider(task).
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostAcquireTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Acquire share form data from form provider(task).
     * @param formId The Id of the form.
     * @param remoteDeviceId The device ID to share.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostShareAcquireTask(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Delete form data from form provider(task).
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostDeleteTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);
   /**
     * @brief Notify provider batch delete.
     * @param formIds The Id list.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObject);
    /**
     * @brief Refresh form data from form provider(task).
     *
     * @param formId The Id of the form.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostRefreshTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Cast temp form data from form provider(task).
     *
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void PostCastTempTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post form data to form host(task) when acquire form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void PostAcquireTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post form data to form host(task) when update form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void PostUpdateTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handel form host died(task).
     * @param remoteHost Form host proxy object.
     */
    void PostHostDiedTask(const sptr<IRemoteObject> &remoteHost);

    /**
     * @brief Post event notify to form provider.
     *
     * @param formEvent The vector of form ids.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param want The want of the form.
     * @param remoteObject The form provider proxy object.
     */
    void PostEventNotifyTask(const std::vector<int64_t> &formEvent, const int32_t formVisibleType, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post message event to form provider.
     * @param formId The Id of the from.
     * @param message Event message.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void PostFormEventTask(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire state to form provider.
    * @param wantArg The want of onAcquireFormState.
    * @param provider The provider info.
    * @param want The want of the request.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireStateTask(const Want &wantArg, const std::string &provider, const Want &want,
                              const sptr <IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire data to form provider.
    * @param formId The Id of the from.
    * @param want The want of the request.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireDataTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

     /**
     * @brief Post uninstall message to form host(task).
     * @param formIds The Id list of the forms.
     * @param remoteObject Form provider proxy object.
     */
    void PostUninstallTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire form state message to form host(task).
    * @param state The form state.
    * @param want The want of onAcquireFormState.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireStateTaskToHost(AppExecFwk::FormState state, const AAFwk::Want &want,
                                    const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post acquire form data message to form host(task).
    * @param wantParams Indicates the data information acquired by the form.
    * @param requestCode Indicates the requested id.
    * @param remoteObject Form provider proxy object.
    */
    void PostAcquireDataTaskToHost(const AAFwk::WantParams &wantParams, int64_t requestCode,
                                    const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Post form share error code to form host(task).
    * @param formShareRequestCode The request code for this share.
    * @param result The error code of this share.
    */
    void PostFormShareSendResponse(int64_t formShareRequestCode, int32_t result);

    void PostRenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void PostStopRenderingForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void PostReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    void PostAddTaskToHost(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    void PostRouterProxyToHost(const int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want);

    void PostRemoveTaskToHost(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);
        
    void PostRefreshForm(const int64_t formId, const Want &want, bool isVisibleToFresh);

    void PostReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    void PostOnUnlock(const sptr<IRemoteObject> &remoteObject);

    void PostSetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject);

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

    /**
    * @brief Post form click event.
    * @param bundleName BundleName of the form host
    * @param formEventType form event type.
    * @param remoteObject thr remote observer.
    * @param runningFormInfo Current form data.
    */
    void PostFormClickEventToHost(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    /**
     * @brief Post recycle forms.
     * @param formIds the Ids of forms to be recycled.
     * @param want The want of the request.
     * @param remoteObjectOfHost Form host proxy object.
     * @param remoteObjectOfRender Form render proxy object.
     */
    void PostRecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost, const sptr<IRemoteObject> &remoteObjectOfRender);

    /**
     * @brief Post recover form.
     * @param formIds the Id of form to be recovered.
     * @param want The want of the request.
     * @param remoteObject Form render proxy object.
     */
    void PostRecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void PostUpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
        const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    void UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth, const std::string &uid,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Cancel delay task.
     * @param eventMsg Delay Task.
     */
    void CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg);

    /**
    * @brief Post BatchRefresh forms.
    * @param formRefreshType batch refresh forms type.
    */
    void PostBatchRefreshForms(const int32_t formRefreshType);

    /**
     * @brief Post enable form task.
     * @param formIds formIds The Id list of the forms.
     * @param enable True or false.
     * @param remoteObject Form host proxy object.
     */
    void PostEnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post task to excute.
     * @param func Task function.
     * @param delayMs Task excute delay time(ms).
     */
    void PostTask(const std::function<void()> &func, uint64_t delayMs = FORM_TASK_DELAY_TIME);

    /**
     * @brief Post re-add form task to form host when FormRenderService is died.
     * @param remoteObject Form host proxy object.
     */
    void PostFrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject);

private:
    /**
     * @brief Acquire form data from form provider.
     * @param formId The Id of the from.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireProviderFormInfo(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Acquire share form data from form provider(task).
     * @param formId The Id of the form.
     * @param remoteDeviceId The device ID to share.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for delete form.
     * @param formId The Id of the from.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     */
    void NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for updating form.
     * @param formId The Id of the from.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     */
    void NotifyFormUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Event notify to form provider.
     *
     * @param formEvents The vector of form ids.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param want The want of the form.
     * @param remoteObject The form provider proxy object.
     */
    void EventNotify(const std::vector<int64_t> &formEvents, const int32_t formVisibleType, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Notify form provider for cast temp form.
     *
     * @param formId The Id of the from.
     * @param want The want of the form.
     * @param remoteObject Form provider proxy object.
     * @return none.
     */
    void NotifyCastTemp(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);
    /**
     * @brief Post form data to form host when acquire form..
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post form data to form host when update form.
     * @param formId The Id of the form.
     * @param record form record.
     * @param remoteObject Form provider proxy object.
     */
    void UpdateTaskToHost(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle form host died.
     * @param remoteHost Form host proxy object.
     */
    void HostDied(const sptr<IRemoteObject> &remoteHost);

    /**
     * @brief Post provider batch delete.
     * @param formIds The Id list.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void ProviderBatchDelete(std::set<int64_t> &formIds, const Want &want, const sptr<IRemoteObject> &remoteObject);
    /**
     * @brief Fire message event to form provider.
     * @param formId The Id of the from.
     * @param message Event message.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Acquire form state to form provider.
     * @param wantArg The want of onAcquireFormState.
     * @param provider The provider info.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
                      const sptr <IRemoteObject> &remoteObject);
    /**
     * @brief Handle acquire data.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireFormDataBack(const AAFwk::WantParams &wantParams, int64_t requestCode,
                            const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Acquire form data to form provider.
     * @param formId The Id of the form.
     * @param want The want of the request.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireFormData(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle uninstall message.
     * @param formIds The Id list of the forms.
     * @param remoteObject Form provider proxy object.
     */
    void FormUninstall(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle acquire state.
     * @param state the form state.
     * @param want The want of onAcquireFormState.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireStateBack(AppExecFwk::FormState state, const AAFwk::Want &want,
                          const sptr <IRemoteObject> &remoteObject);

    /**
     * @brief Create form data for form host.
     * @param formId The Id of the form.
     * @param record Form record.
     * @return Form data.
     */
    FormJsInfo CreateFormJsInfo(const int64_t formId, const FormRecord &record);

    /**
    * @brief Post form share error code to form host(task).
    * @param formShareRequestCode The request code for this share.
    * @param result The error code of this share.
    */
    void FormShareSendResponse(int64_t formShareRequestCode, int32_t result);

    /**
    * @brief Post form share error code to form host(task).
    * @param formShareRequestCode The request code for this share.
    * @param result The error code of this share.
    */
    void RenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void StopRenderingForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject);

    void ReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    void FormAdd(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    void FormRemove(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
        const RunningFormInfo &runningFormInfo);

    void ReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject);

    void OnUnlock(const sptr<IRemoteObject> &remoteObject);

    void SetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject);

    void RemoveConnection(int32_t connectId);

    /**
     * @brief Form router event proxy.
     * @param formId The id of the form.
     * @param remoteObject Form router proxy manager object.
     * @param want The want of the form for router event.
     */
    void FormRouterEventProxy(const int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want);

    /**
    * @brief Form visible/invisible notify.
    * @param formIds  the Ids of forms need to notify.
    * @param formInstanceMaps formInstances for visibleNotify.
    * @param eventMaps eventMaps for event notify.
    * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
    * @param callerToken Caller ability token.
    */
    void NotifyVisible(const std::vector<int64_t> &formIds,
        std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
        std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
        const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Handle recycle form message.
     * @param formId The Id of form to be recycled.
     * @param remoteObjectOfHost Form host proxy object.
     * @param remoteObjectOfRender Form render proxy object.
     */
    void RecycleForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost,
        const sptr<IRemoteObject> &remoteObjectOfRender);

    /**
     * @brief Handle recover form message.
     * @param formId The Id of form to be recovered.
     * @param want The want of the request.
     * @param remoteObject Form render proxy object.
     */
    void RecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject);

    /**
    * @brief Notify remote observer form click event.
    * @param bundleName BundleName of the form host
    * @param formEventType  form event type.
    * @param remoteObject thr remote observer.
    * @param runningFormInfo Current form data.
    */
    void FormClickEvent(const std::string &bundleName, const std::string &formEventType,
        const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo);

    /**
     * @brief Enable form or disable form.
     * @param formIds formIds The Id list of the forms.
     * @param enable True or false.
     * @param remoteObject Form host proxy object.
     */
    void EnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Post re-add form task to form host when FormRenderService is died.
     * @param remoteObject Form host proxy object.
     */
    void FrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject);

private:
    std::mutex formRecoverTimesMutex_;
    std::unordered_map<int64_t, int64_t> formLastRecoverTimes;
    std::shared_ptr<FormSerialQueue> serialQueue_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_TASK_MGR_H
