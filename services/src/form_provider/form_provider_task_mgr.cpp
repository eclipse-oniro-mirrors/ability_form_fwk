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

#include "form_provider/form_provider_task_mgr.h"
#include "form_provider_interface.h"
#include "form_mgr/form_mgr_adapter.h"
#include "form_provider/form_supply_callback.h"
#include "form_provider/form_provider_queue.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_report.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormProviderTaskMgr::FormProviderTaskMgr() {}

FormProviderTaskMgr::~FormProviderTaskMgr() {}

/**
 * @brief Acquire form data from form provider(task).
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::PostAcquireTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireProviderFormInfoFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().AcquireProviderFormInfo(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireProviderFormInfoFunc);
}

/**
 * @brief Refresh form location data from form provider(task).
 *
 * @param formId The Id of the form.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::PostRefreshLocationTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("Call.");
    auto notifyFormLocationUpdateFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().NotifyFormLocationUpdate(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, notifyFormLocationUpdateFunc);
}

/**
 * @brief Refresh form data from form provider(task).
 *
 * @param formId The Id of the form.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::PostRefreshTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call, formId:%{public}" PRId64, formId);

    auto notifyFormUpdateFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().NotifyFormUpdate(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, notifyFormUpdateFunc);
}

/**
 * @brief Delete form data from form provider(task).
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::PostDeleteTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto notifyFormDeleteFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().NotifyFormDelete(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, notifyFormDeleteFunc);
}

/**
 * @brief Post provider batch delete.
 * @param formIds The Id list.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::PostProviderBatchDeleteTask(std::set<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto batchDeleteFunc = [formIds, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().ProviderBatchDelete(formIds, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, batchDeleteFunc);
}

/**
 * @brief Cast temp form data from form provider(task).
 *
 * @param formId The Id of the form.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::PostCastTempTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto notifyCastTempFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().NotifyCastTemp(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, notifyCastTempFunc);
}

/**
* @brief Post acquire state to form provider.
* @param wantArg The want of onAcquireFormState.
* @param provider The provider info.
* @param want The want of the request.
* @param remoteObject Form provider proxy object.
*/
void FormProviderTaskMgr::PostAcquireStateTask(const Want &wantArg, const std::string &provider, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireStateFunc = [wantArg, provider, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().AcquireState(wantArg, provider, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireStateFunc);
}

/**
* @brief Post acquire data to form provider.
* @param formId The Id of the from.
* @param want The want of the request.
* @param remoteObject Form provider proxy object.
*/
void FormProviderTaskMgr::PostAcquireDataTask(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto acquireDataFunc = [formId, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().AcquireFormData(formId, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireDataFunc);
}

/**
 * @brief Post message event to form provider.
 * @param formId The Id of the from.
 * @param message Event message.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::PostFormEventTask(const int64_t formId, const std::string &message,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto formEventFunc = [formId, message, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().FireFormEvent(formId, message, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, formEventFunc);
}

/**
 * @brief Post event notify to form provider.
 * @param formEvent The vector of form ids.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @param want The want of the form.
 * @param remoteObject The form provider proxy object.
 */
void FormProviderTaskMgr::PostEventNotifyTask(const std::vector<int64_t> &formEvent, const int32_t formVisibleType,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto eventNotifyFunc = [formEvent, formVisibleType, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().EventNotify(formEvent, formVisibleType, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, eventNotifyFunc);
}

/**
 * @brief Post size changed to form provider.
 * @param formId The Id of the form to update.
 * @param newDimension The dimension value to be updated.
 * @param newRect The rect value to be updated.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::PostSizeChangedTask(const int64_t formId, const int32_t newDimension,
    const Rect &newRect, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("Call.");
    auto sizeChangedFunc = [formId, newDimension, newRect, want, remoteObject]() {
        FormProviderTaskMgr::GetInstance().NotifySizeChanged(formId, newDimension, newRect, want, remoteObject);
    };
    FormProviderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, sizeChangedFunc);
}

/**
 * @brief Acquire provider formInfo.
 * @param formId The Id of the from.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::AcquireProviderFormInfo(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }
    FormRecord formRecord;
    FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, formRecord, formJsInfo);
    int error = formProviderProxy->AcquireProviderFormInfo(formJsInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail acquire providerFormInfo");
    } else {
        DelayedFormExitDetect(connectId);
    }
    FormReport::GetInstance().SetEndGetTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
}

/**
 * @brief Notify form provider for updating form.
 *
 * @param formId The Id of the from.
 * @param want The want of the form.
 * @param remoteObject Form provider proxy object.
 * @return none.
 */
void FormProviderTaskMgr::NotifyFormUpdate(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    HILOG_INFO("call, formId:%{public}" PRId64", connectId:%{public}d" , formId, connectId);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }
    int error = formProviderProxy->NotifyFormUpdate(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail notify form update");
        return;
    }

    DelayedFormExitDetect(connectId);
}

/**
 * @brief Post provider delete.
 * @param formIds The Id list.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::NotifyFormDelete(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        HILOG_ERROR("get formProviderProxy failed");
        RemoveConnection(connectId);
        return;
    }
    int error = formProviderProxy->NotifyFormDelete(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        HILOG_ERROR("fail NotifyFormDelete");
        RemoveConnection(connectId);
        return;
    }

    DelayedFormExitDetect(connectId);
}

/**
 * @brief Post provider batch delete.
 * @param formIds The Id list.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::ProviderBatchDelete(std::set<int64_t> formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    if (formIds.empty()) {
        HILOG_ERROR("FormIds is empty");
        return;
    }
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("Failed to get formProviderProxy");
        return;
    }
    std::vector<int64_t> vFormIds;
    vFormIds.assign(formIds.begin(), formIds.end());
    int error = formProviderProxy->NotifyFormsDelete(vFormIds, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail");
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
void FormProviderTaskMgr::NotifyCastTemp(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int error = formProviderProxy->NotifyFormCastTempForm(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("acquire providerFormInfo failed");
        return;
    }

    DelayedFormExitDetect(connectId);
}

/**
 * @brief Acquire form state to form provider.
 * @param wantArg The want of onAcquireFormState.
 * @param provider The provider info.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int error = formProviderProxy->AcquireState(wantArg, provider, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("acquire formState failed");
        return;
    }

    DelayedFormExitDetect(connectId);
    HILOG_INFO("end");
}

/**
 * @brief Acquire form data to form provider.
 * @param formId The Id of the form.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::AcquireFormData(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_ACQUIRE_DATA_REQUEST_CODE, 0));
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("null formProviderProxy");
        return;
    }

    int error = formProviderProxy->AcquireFormData(formId, FormSupplyCallback::GetInstance(), requestCode);
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail acquire formStateToFormProvider");
    }
    RemoveConnection(connectId);
    HILOG_INFO("end");
}

/**
 * @brief Fire message event to form provider.
 * @param formId The Id of the from.
 * @param message Event message.
 * @param want The want of the request.
 * @param remoteObject Form provider proxy object.
 */
void FormProviderTaskMgr::FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int error = formProviderProxy->FireFormEvent(formId, message, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fire messageEvent to formProvider failed");
        return;
    }

    DelayedFormExitDetect(connectId);
}

/**
 * @brief Event notify to form provider.
 * @param formEvents The vector of form ids.
 * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
 * @param want The want of the form.
 * @param remoteObject The form provider proxy object.
 */
void FormProviderTaskMgr::EventNotify(const std::vector<int64_t> &formEvents, const int32_t formVisibleType,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int error = formProviderProxy->EventNotify(formEvents, formVisibleType, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail send event notify");
        return;
    }

    DelayedFormExitDetect(connectId);
}

void FormProviderTaskMgr::RemoveConnection(int32_t connectId)
{
    auto formSupplyCallback = FormSupplyCallback::GetInstance();
    if (formSupplyCallback == nullptr) {
        HILOG_ERROR("formSupplyCallback is nullptr.");
        return;
    }
    formSupplyCallback->RemoveConnection(connectId);
}

void FormProviderTaskMgr::NotifyConfigurationUpdate(const AppExecFwk::Configuration& configuration,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int error = formProviderProxy->NotifyConfigurationUpdate(configuration, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("acquire providerFormInfo failed");
        return;
    }

    DelayedFormExitDetect(connectId);
}

void FormProviderTaskMgr::PostBatchConfigurationUpdateForms(const AppExecFwk::Configuration& configuration)
{
    HILOG_INFO("Call.");
    auto batchConfigurationUpdate = [configuration]() {
        return FormMgrAdapter::GetInstance().BatchNotifyFormsConfigurationUpdate(configuration);
    };
    HILOG_INFO("end");
}

void FormProviderTaskMgr::NotifyFormLocationUpdate(const int64_t formId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }
    int error = formProviderProxy->NotifyFormLocationUpdate(formId, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail notify form update");
        return;
    }

    DelayedFormExitDetect(connectId);
}

void FormProviderTaskMgr::NotifySizeChanged(const int64_t formId, const int32_t newDimension,
    const Rect &newRect, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);
    if (formProviderProxy == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }
    int error = formProviderProxy->NotifySizeChanged(formId, newDimension, newRect,
        want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail notify form update");
        return;
    }

    DelayedFormExitDetect(connectId);
}

void FormProviderTaskMgr::DelayedFormExitDetect(int32_t connectId)
{
    auto detectFunc = [connectId]() {
        HILOG_INFO("form exit timeout, handle it. connectId:%{public}d", connectId);
        FormProviderTaskMgr::GetInstance().RemoveConnection(connectId);
    };
    FormProviderQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(Constants::DETECT_FORM_EXIT_DELAY_TASK, static_cast<int64_t>(connectId)),
        Constants::DETECT_FORM_EXIT_TIMEOUT_DELAY, detectFunc);
}
} // namespace AppExecFwk
} // namespace OHOS