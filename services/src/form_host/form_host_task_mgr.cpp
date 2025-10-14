/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "form_host/form_host_task_mgr.h"

#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "form_host/form_host_queue.h"
#include "data_center/form_data_mgr.h"
#include "form_provider/form_supply_callback.h"

namespace OHOS {
namespace AppExecFwk {
FormHostTaskMgr::FormHostTaskMgr() {}

FormHostTaskMgr::~FormHostTaskMgr() {}

/**
 * @brief Post form data to form host(task) when acquire form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::PostAcquireTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireTaskToHostFunc = [formId, record, remoteObject]() {
        FormHostTaskMgr::GetInstance().AcquireTaskToHost(formId, record, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireTaskToHostFunc);
}

/**
 * @brief Post form data to form host(task) when update form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::PostUpdateTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto updateTaskToHostFunc = [formId, record, remoteObject]() {
        FormHostTaskMgr::GetInstance().UpdateTaskToHost(formId, record, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, updateTaskToHostFunc);
}

/**
 * @brief Post uninstall message to form host(task).
 * @param formIds The Id list of the forms.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::PostUninstallTaskToHost(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto uninstallFunc = [formIds, remoteObject]() {
        FormHostTaskMgr::GetInstance().FormUninstall(formIds, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, uninstallFunc);
}

/**
* @brief Post acquire form state message to form host(task).
* @param state The form state.
* @param want The want of onAcquireFormState.
* @param remoteObject Form provider proxy object.
*/
void FormHostTaskMgr::PostAcquireStateTaskToHost(AppExecFwk::FormState state, const AAFwk::Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireStateFunc = [state, want, remoteObject]() {
        FormHostTaskMgr::GetInstance().AcquireStateBack(state, want, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireStateFunc);
}

/**
 * @brief Post acquire form data message to form host(task).
 * @param wantParams Indicates the data information acquired by the form.
 * @param requestCode Indicates the requested id.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::PostAcquireDataTaskToHost(const AAFwk::WantParams &wantParams,
    int64_t requestCode, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireTaskToHostFunc = [wantParams, requestCode, remoteObject]() {
        FormHostTaskMgr::GetInstance().AcquireFormDataBack(wantParams, requestCode, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireTaskToHostFunc);
}

/**
 * @brief Post enable form task.
 * @param formIds formIds The Id list of the forms.
 * @param enable True or false.
 * @param remoteObject Form host proxy object.
 */
void FormHostTaskMgr::PostEnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto enableFormsTaskToHostFunc = [formIds, enable, remoteObject]() {
        FormHostTaskMgr::GetInstance().EnableFormsTaskToHost(formIds, enable, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, enableFormsTaskToHostFunc);
}

/**
 * @brief Post lock form task.
 * @param formIds formIds The Id list of the forms.
 * @param lock True or false.
 * @param remoteObject Form host proxy object.
 */
void FormHostTaskMgr::PostLockFormsTaskToHost(const std::vector<int64_t> &formIds, const bool lock,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto lockFormsTaskToHostFunc = [formIds, lock, remoteObject]() {
        FormHostTaskMgr::GetInstance().LockFormsTaskToHost(formIds, lock, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, lockFormsTaskToHostFunc);
}

/**
 * @brief Post re-add form task to form host when FormRenderService is died.
 * @param remoteObject Form host proxy object.
 */
void FormHostTaskMgr::PostFrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto task = [remoteObject]() {
        FormHostTaskMgr::GetInstance().FrsDiedTaskToHost(remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_FRS_DIED_TASK_DELAY_TIME, task);
}

/**
 * @brief Post re-add form task to form host when FormRenderService is died.
 * @param formId The Id of the form.
 * @param errorCode Indicates error-code of the form.
 */
void FormHostTaskMgr::PostConnectFRSFailedTaskToHost(int64_t formId, int32_t errorCode)
{
    auto task = [formId, errorCode]() {
        FormHostTaskMgr::GetInstance().ConnectFRSFailedTaskToHost(formId, errorCode);
    };
    const std::pair<int64_t, int64_t> eventMsg = std::make_pair((int64_t)TaskType::RENDER_FORM, formId);
    FormHostQueue::GetInstance().CancelDelayTask(eventMsg);
    FormHostQueue::GetInstance().ScheduleDelayTask(eventMsg, FORM_FRS_DIED_TASK_DELAY_TIME, task);
}

/**
 * @brief Handle form host died(task).
 * @param remoteHost Form host proxy object.
 */
void FormHostTaskMgr::PostHostDiedTask(const sptr<IRemoteObject> &remoteHost)
{
    HILOG_DEBUG("call");

    auto postTaskFunc = [remoteHost]() {
        FormHostTaskMgr::GetInstance().HostDied(remoteHost);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, postTaskFunc);
}

/**
 * @brief Post form data to form host when acquire form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::AcquireTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, record, formJsInfo);
    HILOG_DEBUG("FormTaskMgr remoteFormHost OnAcquired");
    remoteFormHost->OnAcquired(formJsInfo, nullptr);
}

/**
 * @brief Post form data to form host when update form.
 * @param formId The Id of the form.
 * @param callingUid Calling uid.
 * @param info Form configure info.
 * @param wantParams WantParams of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::UpdateTaskToHost(const int64_t formId, const FormRecord &record,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, record, formJsInfo);
    remoteFormHost->OnUpdate(formJsInfo);
    HILOG_DEBUG("end");
}

/**
 * @brief Handle uninstall message.
 * @param formIds The Id list of the forms.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::FormUninstall(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnUninstall(formIds);
    HILOG_DEBUG("end");
}

/**
 * @brief Handle acquire state.
 * @param state the form state.
 * @param want The want of onAcquireFormState.
 * @param remoteObject Form provider proxy object.
 */
void FormHostTaskMgr::AcquireStateBack(AppExecFwk::FormState state, const AAFwk::Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnAcquireState(state, want);
    HILOG_DEBUG("end");
}

/**
* @brief Handle acquire data.
* @param wantParams Indicates the data information acquired by the form.
* @param requestCode Indicates the requested id.
* @param remoteObject Form provider proxy object.
*/
void FormHostTaskMgr::AcquireFormDataBack(const AAFwk::WantParams &wantParams,
    int64_t requestCode, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnAcquireDataResponse(wantParams, requestCode);
    HILOG_DEBUG("end");
}

void FormHostTaskMgr::EnableFormsTaskToHost(const std::vector<int64_t> &formIds, const bool enable,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnEnableForm(formIds, enable);
    HILOG_DEBUG("end");
}

void FormHostTaskMgr::LockFormsTaskToHost(const std::vector<int64_t> &formIds, const bool lock,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    HILOG_INFO("LockFormsTaskToHost start");
    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnLockForm(formIds, lock);
    HILOG_DEBUG("end");
}

void FormHostTaskMgr::FrsDiedTaskToHost(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnError(ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, "FormRenderService is dead.");
    HILOG_DEBUG("end");
}

void FormHostTaskMgr::ConnectFRSFailedTaskToHost(int64_t formId, int32_t errorCode)
{
    HILOG_WARN("formId:%{public}" PRId64 ", errorCode:%{public}d", formId, errorCode);
    std::vector<int64_t> formIds{formId};

    std::vector<sptr<IRemoteObject>> formHostObjs;
    FormDataMgr::GetInstance().GetFormHostRemoteObj(formId, formHostObjs);
    for (const auto &host : formHostObjs) {
        auto hostClient = iface_cast<IFormHost>(host);
        if (hostClient == nullptr) {
            HILOG_ERROR("null hostClient");
            continue;
        }
        hostClient->OnError(errorCode, "Connect FormRenderService failed", formIds);
    }
}

void FormHostTaskMgr::HostDied(const sptr<IRemoteObject> &remoteHost)
{
    HILOG_INFO("remote client died event");

    if (remoteHost == nullptr) {
        HILOG_ERROR("remote client died, invalid param");
        return;
    }
    FormDataMgr::GetInstance().HandleHostDied(remoteHost);
    FormSupplyCallback::GetInstance()->HandleHostDied(remoteHost);
}

void FormHostTaskMgr::PostDueControlFormsTaskToHost(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
    const bool isControl, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto func = [formIds, isDisablePolicy, isControl, remoteObject]() {
        FormHostTaskMgr::GetInstance().DueControlFormsTaskToHost(formIds, isDisablePolicy, isControl, remoteObject);
    };
    FormHostQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, func);
}

void FormHostTaskMgr::DueControlFormsTaskToHost(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
    const bool isControl, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(remoteObject);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }

    remoteFormHost->OnDueControlForm(formIds, isDisablePolicy, isControl);
    HILOG_DEBUG("end");
}
} // namespace AppExecFwk
} // namespace OHOS