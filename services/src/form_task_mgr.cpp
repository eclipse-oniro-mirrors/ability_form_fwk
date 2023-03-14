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

#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_host_interface.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider_interface.h"
#include "form_render_interface.h"
#include "form_share_mgr.h"
#include "form_supply_callback.h"
#include "hilog_wrapper.h"

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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate", __func__);
        return;
    }
    auto acquireProviderFormInfoFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireProviderFormInfo(formId, want, remoteObject);
    };
    eventHandler_->PostTask(acquireProviderFormInfoFunc, FORM_TASK_DELAY_TIME);
}

void FormTaskMgr::PostShareAcquireTask(int64_t formId, const std::string &remoteDeviceId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_SHARE_REQUEST_CODE, 0));
        PostFormShareSendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
        return;
    }

    auto acquireShareProviderFormInfoFunc = [formId, remoteDeviceId, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    };
    eventHandler_->PostTask(acquireShareProviderFormInfoFunc, FORM_TASK_DELAY_TIME);
}
/**
 * @brief Delete form data from form provider(task).
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostDeleteTask(const int64_t formId, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate", __func__);
        return;
    }
    auto notifyFormDeleteFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyFormDelete(formId, want, remoteObject);
    };
    eventHandler_->PostTask(notifyFormDeleteFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto notifyFormUpdateFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyFormUpdate(formId, want, remoteObject);
    };
    eventHandler_->PostTask(notifyFormUpdateFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate", __func__);
        return;
    }
    auto notifyCastTempFunc = [formId, want, remoteObject]() {
        FormTaskMgr::GetInstance().NotifyCastTemp(formId, want, remoteObject);
    };
    eventHandler_->PostTask(notifyCastTempFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate", __func__);
        return;
    }
    auto acquireTaskToHostFunc = [formId, record, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireTaskToHost(formId, record, remoteObject);
    };
    eventHandler_->PostTask(acquireTaskToHostFunc, FORM_TASK_DELAY_TIME);
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

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }

    HILOG_DEBUG("%{public}s, post the task of updateTaskToHostFunc.", __func__);
    auto updateTaskToHostFunc = [formId, record, remoteObject]() {
        FormTaskMgr::GetInstance().UpdateTaskToHost(formId, record, remoteObject);
    };
    eventHandler_->PostTask(updateTaskToHostFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate", __func__);
        return;
    }
    auto postTaskFunc = [remoteHost]() {
        FormTaskMgr::GetInstance().HostDied(remoteHost);
    };
    eventHandler_->PostTask(postTaskFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto eventNotifyFunc = [formEvent, formVisibleType, want, remoteObject]() {
        FormTaskMgr::GetInstance().EventNotify(formEvent, formVisibleType, want, remoteObject);
    };
    eventHandler_->PostTask(eventNotifyFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto batchDeleteFunc = [&formIds, want, remoteObject]() {
        FormTaskMgr::GetInstance().ProviderBatchDelete(formIds, want, remoteObject);
    };
    eventHandler_->PostTask(batchDeleteFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto formEventFunc = [formId, message, want, remoteObject]() {
        FormTaskMgr::GetInstance().FireFormEvent(formId, message, want, remoteObject);
    };
    eventHandler_->PostTask(formEventFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto acquireStateFunc = [wantArg, provider, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireState(wantArg, provider, want, remoteObject);
    };
    eventHandler_->PostTask(acquireStateFunc, FORM_TASK_DELAY_TIME);
}

/**
 * @brief Post uninstall message to form host(task).
 * @param formIds The Id list of the forms.
 * @param remoteObject Form provider proxy object.
 */
void FormTaskMgr::PostUninstallTaskToHost(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto uninstallFunc = [formIds, remoteObject]() {
        FormTaskMgr::GetInstance().FormUninstall(formIds, remoteObject);
    };
    eventHandler_->PostTask(uninstallFunc, FORM_TASK_DELAY_TIME);
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
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("%{public}s fail, event handler invalidate.", __func__);
        return;
    }
    auto acquireStateFunc = [state, want, remoteObject]() {
        FormTaskMgr::GetInstance().AcquireStateBack(state, want, remoteObject);
    };
    eventHandler_->PostTask(acquireStateFunc, FORM_TASK_DELAY_TIME);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostFormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    HILOG_INFO("%{public}s start", __func__);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return;
    }

    auto formShareSendResponseFunc = [formShareRequestCode, result]() {
        FormTaskMgr::GetInstance().FormShareSendResponse(formShareRequestCode, result);
    };
    eventHandler_->PostTask(formShareSendResponseFunc, FORM_TASK_DELAY_TIME);
    HILOG_INFO("%{public}s end", __func__);
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
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }
    int error = formProviderProxy->NotifyFormUpdate(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
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
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->EventNotify(formEvents, formVisibleType, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
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
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->NotifyFormCastTempForm(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
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
    HILOG_INFO("%{public}s called.", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get formProviderProxy", __func__);
        return;
    }
    std::vector<int64_t> vFormIds;
    vFormIds.assign(formIds.begin(), formIds.end());
    int error = formProviderProxy->NotifyFormsDelete(vFormIds, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
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
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->FireFormEvent(formId, message, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
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
    FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to get formProviderProxy", __func__);
        return;
    }

    int error = formProviderProxy->AcquireState(wantArg, provider, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s, Failed to acquire form state to form provider", __func__);
    }
    HILOG_INFO("%{public}s end", __func__);
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
 * @brief Create form data for form host.
 * @param formId The Id of the form.
 * @param record Form record.
 * @return Form data.
 */
FormJsInfo FormTaskMgr::CreateFormJsInfo(const int64_t formId, const FormRecord &record)
{
    HILOG_INFO("%{public}s start", __func__);
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
    HILOG_DEBUG("%{public}s end, jsPath: %{private}s, data: %{public}s", __func__,
        form.jsFormCodePath.c_str(), form.formData.c_str());
    return form;
}

void FormTaskMgr::FormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    DelayedSingleton<FormShareMgr>::GetInstance()->SendResponse(formShareRequestCode, result);
}

void FormTaskMgr::PostRenderForm(const FormRecord &formRecord, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return;
    }

    auto renderForm = [formRecord, want, remoteObject]() {
        FormTaskMgr::GetInstance().RenderForm(formRecord, want, remoteObject);
    };
    eventHandler_->PostTask(renderForm, FORM_TASK_DELAY_TIME);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::RenderForm(const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    FormJsInfo formJsInfo = CreateFormJsInfo(formRecord.formId, formRecord);
    int32_t error = remoteFormRender->RenderForm(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to add form renderer", __func__);
        return;
    }

    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostStopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s start", __func__);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return;
    }

    auto deleterenderForm = [formRecord, want, remoteObject]() {
        FormTaskMgr::GetInstance().StopRenderingForm(formRecord, want, remoteObject);
    };
    eventHandler_->PostTask(deleterenderForm, FORM_TASK_DELAY_TIME);
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::StopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }

    FormJsInfo formJsInfo = CreateFormJsInfo(formRecord.formId, formRecord);
    int32_t error = remoteFormDeleteRender->StopRenderingForm(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        HILOG_ERROR("%{public}s fail, Failed to add form renderer", __func__);
        return;
    }

    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::ReloadForm(const std::vector<int64_t> &&formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("%{public}s fail, Failed to get form render proxy.", __func__);
        return;
    }
    int32_t error = remoteFormRender->ReloadForm(std::forward<decltype(formIds)>(formIds), want);
    if (error != ERR_OK) {
        HILOG_ERROR("%{public}s fail, Failed to reload form.", __func__);
        return;
    }
    HILOG_INFO("%{public}s end", __func__);
}

void FormTaskMgr::PostReloadForm(const std::vector<int64_t> &&formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("%{public}s begin", __func__);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return;
    }
    auto reloadForm = [ids = std::forward<decltype(formIds)>(formIds), want, remoteObject]() {
        FormTaskMgr::GetInstance().ReloadForm(std::move(ids), want, remoteObject);
    };
    eventHandler_->PostTask(reloadForm, FORM_TASK_DELAY_TIME);
    HILOG_INFO("%{public}s end", __func__);
}
} // namespace AppExecFwk
} // namespace OHOS
