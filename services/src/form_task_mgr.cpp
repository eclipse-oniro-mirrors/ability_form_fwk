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

#include "form_task_mgr.h"

#include <cinttypes>
#include <utility>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_host_delegate_proxy.h"
#include "form_host_interface.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider_interface.h"
#include "form_render_interface.h"
#include "form_serial_queue.h"
#include "form_share_mgr.h"
#include "form_supply_callback.h"
#include "js_form_state_observer_interface.h"
#include "form_info_rdb_storage_mgr.h"
#include "form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_TASK_DELAY_TIME = 20; // ms
} // namespace
FormTaskMgr::FormTaskMgr() {}
FormTaskMgr::~FormTaskMgr() {}
/**
 * @brief Acquire form data from form provider(task).
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostAcquireTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate", __func__);
        return;
    }
    auto acquireProviderFormInfoFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireProviderFormInfo(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireProviderFormInfoFunc);
}

void FormTaskMgr::PostShareAcquireTask(int64_t formId, const std::string &remoteDeviceId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr");
        int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_SHARE_REQUEST_CODE, 0));
        PostFormShareSendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
        return;
    }

    auto acquireShareProviderFormInfoFunc = [formId, remoteDeviceId, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireShareProviderFormInfoFunc);
}
/**
 * @brief Delete form data from form provider(task).
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostDeleteTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate", __func__);
        return;
    }
    auto notifyFormDeleteFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyFormDelete(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, notifyFormDeleteFunc);
}

/**
 * @brief Refresh form data from form provider(task).
 *
 * @param formId The Id of the form.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormTaskMgr::PostRefreshTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto notifyFormUpdateFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyFormUpdate(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, notifyFormUpdateFunc);
}

/**
 * @brief Cast temp form data from form provider(task).
 *
 * @param formId The Id of the form.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormTaskMgr::PostCastTempTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate", __func__);
        return;
    }
    auto notifyCastTempFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyCastTemp(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, notifyCastTempFunc);
}

/**
 * @brief Post form data to form host(task) when acquire form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostAcquireTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate", __func__);
        return;
    }
    auto acquireTaskToHostFunc = [formId, record, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireTaskToHost(formId, record, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireTaskToHostFunc);
}

void FormTaskMgr::PostAcquireDataTaskToHost(const AAFwk::WantParams &wantParams,
    int64_t requestCode, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("failed, serialQueue_ invalidate");
        return;
    }
    auto acquireTaskToHostFunc = [wantParams, requestCode, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireFormDataBack(wantParams, requestCode, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireTaskToHostFunc);
}

/**
 * @brief Post form data to form host(task) when update form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostUpdateTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s called.", __func__);

    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }

    HILOG_DEBUG("%{public}s, post the task of updateTaskToHostFunc.", __func__);
    auto updateTaskToHostFunc = [formId, record, remoteObject]() {
        FormTaskMgr::GetInstance().UpdateTaskToHost(formId, record, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, updateTaskToHostFunc);
}

/**
 * @brief Acquire form data from form provider.
 * @param formId The Id of the form.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
/**
 * @brief Handle form host died(task).
 * @param remoteHost Form host proxy object.
 */
void FormTaskMgr::PostHostDiedTask(const sptr<IRemoteObject> &remoteHost)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate", __func__);
        return;
    }
    auto postTaskFunc = [remoteHost]() {
        FormTaskMgr::GetInstance().HostDied(remoteHost);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, postTaskFunc);
}

/**
 * @brief Post event notify to form provider.
 *
 * @param formEvent The vector of form ids.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @param want The want of the form.
 * @param remoteObject The form provider proxy object.
 * @return none.
 */
void FormTaskMgr::PostEventNotifyTask(const std::vector<int64_t> &formEvent, const int32_t formVisibleType,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto eventNotifyFunc = [formEvent, formVisibleType, want, remoteObject]() {
        FormTaskMgr::GetInstance().EventNotify(formEvent, formVisibleType, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, eventNotifyFunc);
}
/**
 * @brief Post provider batch delete.
 * @param formIds The Id list.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto batchDeleteFunc = [&formIds, want, remoteObject]() {
        FormTaskMgr::GetInstance().ProviderBatchDelete(formIds, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, batchDeleteFunc);
}
/**
 * @brief Post message event to form provider.
 * @param formId The Id of the from.
 * @param message Event message.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostFormEventTask(const int64_t formId, const std::string &message,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto formEventFunc = [formId, message, want, remoteObject]() {
        FormTaskMgr::GetInstance().FireFormEvent(formId, message, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, formEventFunc);
}

/**
* @brief Post acquire state to form provider.
* @param wantArg The want of onAcquireFormState.
* @param provider The provider info.
* @param want The want of the request.
* @param remoteObject Form provider proxy object.
*/
void FormTaskMgr::PostAcquireStateTask(const Want &wantArg, const std::string &provider, const Want &want,
                                       const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto acquireStateFunc = [wantArg, provider, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireState(wantArg, provider, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireStateFunc);
}

/**
* @brief Post acquire data to form provider.
* @param formId The Id of the from.
* @param want The want of the request.
* @param remoteObject Form provider proxy object.
*/
void FormTaskMgr::PostAcquireDataTask(const int64_t formId, const Want &want,
                                      const sptr<IRemoteObject> &remoteObject)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("fail, serialQueue_ invalidate.");
        return;
    }
    auto acquireDataFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireFormData(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireDataFunc);
}

/**
 * @brief Post uninstall message to form host(task).
 * @param formIds The Id list of the forms.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostUninstallTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto uninstallFunc = [formIds, remoteObject]() {
        FormTaskMgr::GetInstance().FormUninstall(formIds, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, uninstallFunc);
    HILOG_INFO("%{public}s end", __func__);
}

/**
* @brief Post acquire form state message to form host(task).
* @param state The form state.
* @param want The want of onAcquireFormState.
* @param remoteObject Form provider proxy object.
*/
void FormTaskMgr::PostAcquireStateTaskToHost(AppExecFwk::FormState state, const AAFwk::Want &want,
                                             const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("%{public}s fail, serialQueue_ invalidate.", __func__);
        return;
    }
    auto acquireStateFunc = [state, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireStateBack(state, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, acquireStateFunc);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostFormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    HILOG_INFO("%{public}s start", __func__);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }

    auto formShareSendResponseFunc = [formShareRequestCode, result]() {
        FormTaskMgr::GetInstance().FormShareSendResponse(formShareRequestCode, result);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, formShareSendResponseFunc);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostAddTaskToHost(const std::string bundleName,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("fail, serialQueue_ invalidate.");
        return;
    }
    auto addFunc = [bundleName, remoteObject, runningFormInfo]() {
        FormTaskMgr::GetInstance().FormAdd(bundleName, remoteObject, runningFormInfo);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, addFunc);
    HILOG_DEBUG("end");
}

void FormTaskMgr::PostRemoveTaskToHost(const std::string bundleName,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("fail, serialQueue_ invalidate.");
        return;
    }
    auto removeFunc = [bundleName, remoteObject, runningFormInfo]() {
        FormTaskMgr::GetInstance().FormRemove(bundleName, remoteObject, runningFormInfo);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, removeFunc);
    HILOG_DEBUG("end");
}

void FormTaskMgr::FormAdd(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");
    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("fail, Failed to get js form state observer proxy.");
        return;
    }
    remoteJsFormStateObserver->OnAddForm(bundleName, runningFormInfo);
    HILOG_DEBUG("end");
}

void FormTaskMgr::FormRemove(const std::string bundleName, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");
    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("fail, Failed to get js form state observer proxy.");
        return;
    }
    remoteJsFormStateObserver->OnRemoveForm(bundleName, runningFormInfo);
    HILOG_DEBUG("end");
}

void FormTaskMgr::AcquireProviderFormInfo(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    FormMgrAdapter::GetInstance().AcquireProviderFormInfo(formId, want, remoteObject);
}

void FormTaskMgr::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    DelayedSingleton<FormShareMgr>::GetInstance()->AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
}
/**
 * @brief Notify form provider for delete form.
 *
 * @param formId The Id of the from.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormTaskMgr::NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    FormMgrAdapter::GetInstance().NotifyFormDelete(formId, want, remoteObject);
}

/**
 * @brief Notify form provider for updating form.
 *
 * @param formId The Id of the from.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormTaskMgr::NotifyFormUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s called.", __func__);

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }
    int error = formProviderProxy->NotifyFormUpdate(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to notify form update.", __func__);
    }
}

/**
 * @brief Event notify to form provider.
 *
 * @param formEvents The vector of form ids.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @param want The want of the form.
 * @param remoteObject The form provider proxy object.
 * @return none.
 */
void FormTaskMgr::EventNotify(const std::vector<int64_t> &formEvents, const int32_t formVisibleType,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s called.", __func__);

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->EventNotify(formEvents, formVisibleType, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to send event notify.", __func__);
    }
}

/**
 * @brief Notify form provider for cast temp form.
 *
 * @param formId The Id of the from.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormTaskMgr::NotifyCastTemp(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s called.", __func__);

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->NotifyFormCastTempForm(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get acquire provider form info", __func__);
    }
}

/**
 * @brief Post form data to form host when acquire form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::AcquireTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("FormTaskMgr AcquireTaskToHost, formId:%{public}" PRId64 "", formId);

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form host proxy", __func__);
        return;
    }

    HILOG_DEBUG("FormTaskMgr remoteFormHost OnAcquired");
    remoteFormHost->OnAcquired(CreateFormJsInfo(formId, record), nullptr);
}

/**
 * @brief Post form data to form host when update form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::UpdateTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start.", __func__);

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form host proxy.", __func__);
        return;
    }

    HILOG_DEBUG("%{public}s, FormTaskMgr remoteFormHost OnUpdate.", __func__);
    remoteFormHost->OnUpdate(CreateFormJsInfo(formId, record));

    HILOG_INFO("%{public}s end.", __func__);
}

/**
 * @brief Handle form host died.
 * @param remoteHost Form host proxy object.
 */
void FormTaskMgr::HostDied(const sptr<IRemoteObject> &remoteHost)
{
    HILOG_INFO("%{public}s, remote client died event", __func__);
    if (remoteHost == nullptr) {
        HILOG_INFO("%{public}s, remote client died, invalid param", __func__);
        return;
    }
    FormDataMgr::GetInstance().HandleHostDied(remoteHost);
    FormSupplyCallback::GetInstance()->HandleHostDied(remoteHost);
}
/**
 * @brief Post provider batch delete.
 * @param formIds The Id list.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::ProviderBatchDelete(std::set<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start.", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get formProviderProxy", __func__);
        return;
    }
    std::vector<int64_t> vFormIds;
    vFormIds.assign(formIds.begin(), formIds.end());
    int error = formProviderProxy->NotifyFormsDelete(vFormIds, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s failed", __func__);
    }
}
/**
 * @brief Fire message event to form provider.
 * @param formId The Id of the from.
 * @param message Event message.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->FireFormEvent(formId, message, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to fire message event to form provider", __func__);
    }
    HILOG_INFO("%{public}s end", __func__);
}

/**
 * @brief Acquire form state to form provider.
 * @param wantArg The want of onAcquireFormState.
 * @param provider The provider info.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
                               const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->AcquireState(wantArg, provider, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to acquire form state to form provider", __func__);
    }
    HILOG_INFO("%{public}s end", __func__);
}

/**
 * @brief Acquire form data to form provider.
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::AcquireFormData(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_ACQUIRE_DATA_REQUEST_CODE, 0));
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("Failed to get formProviderProxy");
        return;
    }

    int error = formProviderProxy->AcquireFormData(formId, FormSupplyCallback::GetInstance(), requestCode);
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("Failed to acquire form state to form provider");
    }
    RemoveConnection(connectId);
    HILOG_INFO("end");
}

/**
 * @brief Handle uninstall message.
 * @param formIds The Id list of the forms.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::FormUninstall(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form host proxy.", __func__);
        return;
    }

    remoteFormHost->OnUninstall(formIds);

    HILOG_INFO("%{public}s end", __func__);
}

/**
 * @brief Handle acquire state.
 * @param state the form state.
 * @param want The want of onAcquireFormState.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::AcquireStateBack(AppExecFwk::FormState state, const AAFwk::Want &want,
                                   const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form host proxy.", __func__);
        return;
    }

    remoteFormHost->OnAcquireState(state, want);

    HILOG_INFO("%{public}s end", __func__);
}

/**
 * @brief Handle acquire data.
* @param wantParams Indicates the data information acquired by the form.
* @param requestCode Indicates the requested id.
* @param remoteObject Form provider proxy object.
*/
void FormTaskMgr::AcquireFormDataBack(const AAFwk::WantParams &wantParams,
    int64_t requestCode, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");
    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("fail, Failed to get form host proxy.");
        return;
    }

    remoteFormHost->OnAcquireDataResponse(wantParams, requestCode);

    HILOG_INFO("end");
}

/**
 * @brief Create form data for form host.
 * @param formId The Id of the form.
 * @param record Form record.
 * @return Form data.
 */
FormJsInfo FormTaskMgr::CreateFormJsInfo(const int64_t formId, const FormRecord &record)
{
    HILOG_DEBUG("create formJsInfo");
    FormJsInfo form;
    form.formId = formId;
    form.bundleName = record.bundleName;
    form.abilityName = record.abilityName;
    form.formName = record.formName;
    form.moduleName = record.moduleName;
    form.formTempFlag = record.formTempFlag;
    form.jsFormCodePath = record.jsFormCodePath;
    form.formData = record.formProviderInfo.GetFormDataString();
    form.formProviderData = record.formProviderInfo.GetFormData();
    form.formSrc = record.formSrc;
    form.formWindow = record.formWindow;
    form.type = record.type;
    form.uiSyntax = record.uiSyntax;
    form.isDynamic = record.isDynamic;
    form.transparencyEnabled = record.transparencyEnabled;
    form.modulePkgNameMap = record.modulePkgNameMap;
    HILOG_DEBUG("%{public}s end, jsPath: %{private}s, data: %{private}s", __func__,
        form.jsFormCodePath.c_str(), form.formData.c_str());
    return form;
}

void FormTaskMgr::FormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    auto formShareMgr = DelayedSingleton<FormShareMgr>::GetInstance();
    if (formShareMgr == nullptr) {
        HILOG_ERROR("formShareMgr is nullptr.");
        return;
    }
    formShareMgr->SendResponse(formShareRequestCode, result);
}

void FormTaskMgr::PostRenderForm(const FormRecord &formRecord, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("PostRenderForm");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }

    auto renderForm = [formRecord, want, remoteObject]() {
        FormTaskMgr::GetInstance().RenderForm(formRecord, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, renderForm);
    HILOG_DEBUG("%{public}s end", __func__);
}

void FormTaskMgr::RenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("render form");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    FormJsInfo formJsInfo = CreateFormJsInfo(formRecord.formId, formRecord);
    int32_t error = remoteFormRender->RenderForm(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to add form renderer", __func__);
        return;
    }

    HILOG_DEBUG("%{public}s end", __func__);
}

void FormTaskMgr::PostStopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("PostStopRenderingForm");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }

    auto deleterenderForm = [formRecord, want, remoteObject]() {
        FormTaskMgr::GetInstance().StopRenderingForm(formRecord, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, deleterenderForm);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::StopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    FormJsInfo formJsInfo = CreateFormJsInfo(formRecord.formId, formRecord);
    int32_t error = remoteFormDeleteRender->StopRenderingForm(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to add form renderer", __func__);
        return;
    }

    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }

    auto deleterenderForm = [formId, compId, uid, remoteObject]() {
        FormTaskMgr::GetInstance().ReleaseRenderer(formId, compId, uid, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, deleterenderForm);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::ReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    int32_t error = remoteFormDeleteRender->ReleaseRenderer(formId, compId, uid);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s fail, Failed to release form renderer", __func__);
        return;
    }
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::ReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    std::vector<FormJsInfo> formJsInfos;
    for (const auto &formRecord : formRecords) {
        FormJsInfo formJsInfo = CreateFormJsInfo(formRecord.formId, formRecord);
        formJsInfos.emplace_back(formJsInfo);
    }

    int32_t error = remoteFormRender->ReloadForm(std::move(formJsInfos), want);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s fail, Failed to reload form.", __func__);
        return;
    }
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }
    auto reloadForm = [forms = std::forward<decltype(formRecords)>(formRecords), want, remoteObject]() {
        FormTaskMgr::GetInstance().ReloadForm(std::move(forms), want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, reloadForm);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::OnUnlock(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("begin");
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }
    int32_t error = remoteFormRender->OnUnlock();
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s fail", __func__);
        return;
    }
    HILOG_DEBUG("end");
}

void FormTaskMgr::PostOnUnlock(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("called");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        return;
    }
    auto task = [remoteObject]() {
        FormTaskMgr::GetInstance().OnUnlock(remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, task);
    HILOG_DEBUG("end");
}

void FormTaskMgr::RemoveConnection(int32_t connectId)
{
    auto formSupplyCallback = FormSupplyCallback::GetInstance();
    if (formSupplyCallback == nullptr) {
        HILOG_ERROR("formSupplyCallback is nullptr.");
        return;
    }
    formSupplyCallback->RemoveConnection(connectId);
}

/**
 * @brief want data from form router event(task).
 * @param formId The id of the form.
 * @param remoteObject Form router proxy manager object.
 * @param want The want of the form for router event.
 */
void FormTaskMgr::PostRouterProxyToHost(const int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("Fail, serialQueue_ invalidate.");
        return;
    }

    auto routerProxyFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().FormRouterEventProxy(formId, remoteObject, want);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, routerProxyFunc);
}

/**
 * @brief Form router event proxy.
 * @param formId The id of the form.
 * @param remoteObject Form router proxy manager object.
 * @param want The want of the form for router event.
 */
void FormTaskMgr::FormRouterEventProxy(const int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want)
{
    if (remoteObject == nullptr) {
        HILOG_ERROR("Fail, remoteObject is nullptr!");
        return;
    }

    sptr<IFormHostDelegate> remoteFormHostDelegateProxy = iface_cast<IFormHostDelegate>(remoteObject);
    if (remoteFormHostDelegateProxy == nullptr) {
        HILOG_ERROR("Fail, remoteFormHostDelegateProxy is nullptr!");
        return;
    }
    remoteFormHostDelegateProxy->RouterEvent(formId, want);
}

/**
 * @brief Post Form visible/invisible notify.
 * @param formIds  the Ids of forms need to notify.
 * @param formInstanceMaps formInstances for visibleNotify.
 * @param eventMaps eventMaps for event notify.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @param visibleNotifyDelay delay time.
 */
void FormTaskMgr::PostVisibleNotify(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> &eventMaps,
    const int32_t formVisibleType, int32_t visibleNotifyDelay)
{
    HILOG_DEBUG("called");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is nullptr.");
        FormTaskMgr::GetInstance().NotifyVisible(formIds, formInstanceMaps, eventMaps, formVisibleType);
        return;
    }
    auto task = [formIds, formInstanceMaps, eventMaps, formVisibleType]() {
        FormTaskMgr::GetInstance().NotifyVisible(formIds, formInstanceMaps, eventMaps, formVisibleType);
    };
    serialQueue_->ScheduleTask(visibleNotifyDelay, task);
    HILOG_DEBUG("end");
}

/**
* @brief Form visible/invisible notify.
* @param formIds  the Ids of forms need to notify.
* @param formInstanceMaps formInstances for visibleNotify.
* @param eventMaps eventMaps for event notify.
* @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
*/
void FormTaskMgr::NotifyVisible(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType)
{
    FormMgrAdapter::GetInstance().HandlerNotifyWhetherVisibleForms(formIds,
        formInstanceMaps, eventMaps, formVisibleType);
}

/**
 * @brief Post recycle forms.
 * @param formIds the Ids of forms to be recycled.
 * @param want The want of the request.
 * @param remoteObjectOfHost Form host proxy object.
 * @param remoteObjectOfRender Form render proxy object.
 */
void FormTaskMgr::PostRecycleForms(const std::vector<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObjectOfHost, const sptr<IRemoteObject> &remoteObjectOfRender)
{
    HILOG_DEBUG("start.");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is null.");
        return;
    }

    auto delayTime = want.GetIntParam(Constants::FORM_DELAY_TIME_OF_RECYCLE, FORM_TASK_DELAY_TIME);
    for (const int64_t &formId : formIds) {
        auto recycleForm = [formId, remoteObjectOfHost, remoteObjectOfRender]() {
            FormTaskMgr::GetInstance().RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
        };
        serialQueue_->ScheduleDelayTask(
            std::make_pair((int64_t)TaskType::RECYCLE_FORM, formId), delayTime, recycleForm);
    }
    HILOG_DEBUG("end");
}

/**
 * @brief Handle recycle form message.
 * @param formId The Id of form to be recycled.
 * @param remoteObjectOfHost Form host proxy object.
 * @param remoteObjectOfRender Form render proxy object.
 */
void FormTaskMgr::RecycleForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost,
    const sptr<IRemoteObject> &remoteObjectOfRender)
{
    HILOG_DEBUG("start.");

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObjectOfRender);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("Failed to get form render proxy, formId is %{public}" PRId64, formId);
        return;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("form %{public}" PRId64 " not exist", formId);
        return;
    }
    if (formRecord.recycleStatus != RecycleStatus::RECYCLABLE) {
        HILOG_ERROR("form %{public}" PRId64 " is not RECYCLABLE", formId);
        return;
    }

    Want want;
    int32_t userId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(userId) + formRecord.bundleName);
    want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, remoteObjectOfHost);
    int32_t error = remoteFormRender->RecycleForm(formId, want);
    if (error != ERR_OK) {
        HILOG_ERROR("fail");
        return;
    }
}

/**
 * @brief Post recover forms.
 * @param formIds the Ids of forms to be recycled.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormTaskMgr::PostRecoverForm(const int64_t &formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start.");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is null.");
        return;
    }

    auto recoverForm = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().RecoverForm(formId, want, remoteObject);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, recoverForm);
    HILOG_DEBUG("end");
}

/**
 * @brief Handle recover form message.
 * @param formId The Id of form to be recovered.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormTaskMgr::RecoverForm(const int64_t &formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start.");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("Failed to get form render proxy.");
        return;
    }

    int32_t error = remoteFormRender->RecoverForm(formId, want);
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("Failed to recover form");
        return;
    }

    HILOG_DEBUG("end");
}
/**
 * @brief Cancel delay task.
 * @param eventMsg Delay Task.
 */
void FormTaskMgr::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    HILOG_DEBUG("cancel delay task: <%{public}" PRId64", %{public}" PRId64">.",
        eventMsg.first, eventMsg.second);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("serialQueue_ is null.");
        return;
    }

    serialQueue_->CancelDelayTask(eventMsg);
    HILOG_DEBUG("end");
}

void FormTaskMgr::PostFormClickEventToHost(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &remoteObject,
    const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("Called.");
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("Fail, serialQueue_ invalidate.");
        return;
    }
    auto task = [bundleName, formEventType, remoteObject, runningFormInfo]() {
        if (remoteObject == nullptr) {
            HILOG_ERROR("Fail, remoteObject is null.");
            return;
        }
        FormTaskMgr::GetInstance().FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
    };
    serialQueue_->ScheduleTask(FORM_TASK_DELAY_TIME, task);
}

void FormTaskMgr::FormClickEvent(const std::string &bundleName, const std::string &formEventType,
    const sptr<IRemoteObject> &remoteObject, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("Called");
    sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
        iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
    if (remoteJsFormStateObserver == nullptr) {
        HILOG_ERROR("Failed to get js form state observer proxy.");
        return;
    }

    remoteJsFormStateObserver->OnFormClickEvent(bundleName, formEventType, runningFormInfo);
}
} // namespace AppExecFwk
} // namespace OHOS
