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

#include "status_mgr_center/form_status_task_mgr.h"
#include "form_render_interface.h"
#include "fms_log_wrapper.h"
#include "common/util/form_util.h"
#include "form_event_report.h"
#include "status_mgr_center/form_status_queue.h"
#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_status.h"
#include "form_mgr/form_mgr_queue.h"
#include "data_center/form_record/form_record_report.h"
#include "form_provider/form_supply_callback.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_cache_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t WAIT_RELEASE_RENDERER_TIMEOUT = 3000;
constexpr int64_t WAIT_RELEASE_RENDERER_MSG = 1;
constexpr int64_t RELEASE_RENDER_DELAY_TIME = 40;
constexpr int64_t RELEASE_RENDER_DELAY_MSG = 2;
}
FormStatusTaskMgr::FormStatusTaskMgr()
{}

FormStatusTaskMgr::~FormStatusTaskMgr()
{}

/**
 * @brief Post recycle forms.
 * @param formIds the Ids of forms to be recycled.
 * @param want The want of the request.
 * @param remoteObjectOfHost Form host proxy object.
 * @param remoteObjectOfRender Form render proxy object.
 */
void FormStatusTaskMgr::PostRecycleForms(const std::vector<int64_t> &formIds, const Want &want,
    const sptr<IRemoteObject> &remoteObjectOfHost, const sptr<IRemoteObject> &remoteObjectOfRender)
{
    HILOG_DEBUG("start");

    for (const int64_t formId : formIds) {
        if (!FormDataMgr::GetInstance().IsExpectRecycled(formId)) {
            HILOG_WARN("form not need recycle, formId: %{public}" PRId64, formId);
            continue;
        }
        auto recycleForm = [formId, remoteObjectOfHost, remoteObjectOfRender]() {
            FormStatusTaskMgr::GetInstance().RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
        };
        FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_DATA, recycleForm);
    }
    HILOG_DEBUG("end");
}

/**
 * @brief Post recover forms.
 * @param formIds the Ids of forms to be recycled.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormStatusTaskMgr::PostRecoverForm(
    const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    auto formId = record.formId;
    auto recoverForm = [record, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().RecoverForm(record, want, remoteObject);
    };
    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECOVER_FORM, recoverForm);
    HILOG_DEBUG("end");
}

/**
 * @brief Post release form.
 * @param formIds The Id of form to be recovered.
 * @param compId The compId of the forms.
 * @param uid calling user id.
 * @param remoteObject Form render proxy object.
 * @param isDynamic isDynamic flag.
 */
void FormStatusTaskMgr::PostReleaseRenderer(int64_t formId, const std::string &compId, const std::string &uid,
    const sptr<IRemoteObject> &remoteObject, bool isDynamic)
{
    HILOG_DEBUG("start");

    auto deleterenderForm = [formId, compId, uid, remoteObject]() {
        FormStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId);
        FormStatusTaskMgr::GetInstance().PostDelayReleaseRenderer(formId, compId, uid, remoteObject);
    };
    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_FORM, deleterenderForm);
    HILOG_DEBUG("end");
}

/**
 * @brief Post render form.
 * @param formRecord The form record.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormStatusTaskMgr::PostRenderForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    auto renderForm = [formRecord, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().RenderForm(formRecord, want, remoteObject);
        FormStatusTaskMgr::GetInstance().RestoreFormRecycledStatus(formRecord, remoteObject);
    };

    FormStatusMgr::GetInstance().PostFormEvent(formRecord.formId, FormFsmEvent::RENDER_FORM, renderForm);
    HILOG_DEBUG("end");
}

/**
 * @brief Post stop rendering form.
 * @param formRecord The form record.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormStatusTaskMgr::PostStopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    auto formId = formRecord.formId;
    auto deleterenderForm = [formRecord, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().StopRenderingForm(formRecord, want, remoteObject);
    };

    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::DELETE_FORM, deleterenderForm);
    HILOG_DEBUG("end");
}

/**
 * @brief Schedules form recycle timeout task
 * @param formId Form ID
 * @return bool Returns true if the timeout was successfully scheduled, false otherwise
 */
bool FormStatusTaskMgr::ScheduleRecycleTimeout(const int64_t formId)
{
    FormStatusQueue::GetInstance().CancelDelayTask(std::make_pair(formId, WAIT_RELEASE_RENDERER_MSG));

    auto timeoutTask = [formId]() {
        HILOG_ERROR("RecycleForm failed, wait form release timeout, formId:%{public}" PRId64, formId);
        FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::UNPROCESSABLE);
        FormStatusQueue::GetInstance().CancelDelayTask(std::make_pair(formId, WAIT_RELEASE_RENDERER_MSG));
    };
    return FormStatusQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(formId, WAIT_RELEASE_RENDERER_MSG), WAIT_RELEASE_RENDERER_TIMEOUT, timeoutTask);
}

/**
 * @brief Cancel form recycle timeout task
 * @param formId Form ID
 * @return bool Returns true if the timeout was successfully canceled, false otherwise
 */
bool FormStatusTaskMgr::CancelRecycleTimeout(const int64_t formId)
{
    return FormStatusQueue::GetInstance().CancelDelayTask(std::make_pair(formId, WAIT_RELEASE_RENDERER_MSG));
}

void FormStatusTaskMgr::RecycleForm(const int64_t &formId, const sptr<IRemoteObject> &remoteObjectOfHost,
    const sptr<IRemoteObject> &remoteObjectOfRender)
{
    HILOG_INFO("start formId: %{public}" PRId64, formId);

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObjectOfRender);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("fail get form render proxy, formId is %{public}" PRId64, formId);
        return;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("form %{public}" PRId64 " not exist", formId);
        return;
    }

    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(formRecord.providerUserId) + formRecord.bundleName);
    want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, remoteObjectOfHost);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    int32_t error = remoteFormRender->RecycleForm(formId, want);
    if (error != ERR_OK) {
        HILOG_ERROR("RecycleForm fail formId: %{public}" PRId64 " error: %{public}d", formId, error);
        FormEventReport::SendFormFailedEvent(FormEventName::RECYCLE_RECOVER_FORM_FAILED,
            formId,
            formRecord.bundleName,
            formRecord.formName,
            static_cast<int32_t>(RecycleRecoverFormErrorType::RECYCLE_FORM_FAILED),
            error);
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_DATA_FAIL);
    }
}

void FormStatusTaskMgr::RecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start formId: %{public}" PRId64, record.formId);

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(record.formId, record, formJsInfo);
    Want newWant(want);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(record.formId);
    newWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);

    int32_t error = remoteFormRender->RecoverForm(formJsInfo, newWant);
    if (error != ERR_OK) {
        HILOG_ERROR("RecoverForm fail formId: %{public}" PRId64 " error: %{public}d", formJsInfo.formId, error);
        RemoveConnection(connectId);
        FormEventReport::SendFormFailedEvent(FormEventName::RECYCLE_RECOVER_FORM_FAILED,
            record.formId,
            record.bundleName,
            record.formName,
            static_cast<int64_t>(RecycleRecoverFormErrorType::RECOVER_FORM_FAILED),
            error);
        FormStatusMgr::GetInstance().CancelFormEventTimeout(record.formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(record.formId, FormFsmEvent::RECOVER_FORM_FAIL);
    }
    HILOG_DEBUG("end");
}

void FormStatusTaskMgr::ReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("begin formId: %{public}" PRId64, formId);

    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    Want newWant;
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    newWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);

    int32_t error = remoteFormDeleteRender->ReleaseRenderer(formId, compId, uid, newWant);
    if (error != ERR_OK) {
        HILOG_ERROR("ReleaseRenderer fail formId: %{public}" PRId64 " error: %{public}d", formId, error);
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RECYCLE_FORM_FAIL);
    }
    HILOG_INFO("end formId: %{public}" PRId64, formId);
}

bool FormStatusTaskMgr::PostDelayReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    FormStatusQueue::GetInstance().CancelDelayTask(std::make_pair(formId, RELEASE_RENDER_DELAY_MSG));

    auto recycleForm = [formId, compId, uid, remoteObject]() {
        FormStatusTaskMgr::GetInstance().ReleaseRenderer(formId, compId, uid, remoteObject);
        FormStatusQueue::GetInstance().CancelDelayTask(std::make_pair(formId, RELEASE_RENDER_DELAY_MSG));
    };
    return FormStatusQueue::GetInstance().ScheduleDelayTask(
        std::make_pair(formId, RELEASE_RENDER_DELAY_MSG), RELEASE_RENDER_DELAY_TIME, recycleForm);
}

void FormStatusTaskMgr::StopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin formId: %{public}" PRId64, formRecord.formId);

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formRecord.formId, formRecord, formInfo);
    Want newWant(want);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formRecord.formId);
    newWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);

    int32_t error = remoteFormDeleteRender->StopRenderingForm(formInfo, newWant, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        HILOG_ERROR("StopRenderingForm fail formId: %{public}" PRId64 " error: %{public}d", formRecord.formId, error);
        RemoveConnection(connectId);
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formInfo.formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formInfo.formId, FormFsmEvent::DELETE_FORM_FAIL);
    }
    HILOG_INFO("end");
}

void FormStatusTaskMgr::RenderForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("render form formId: %{public}" PRId64 ",%{public}zu", formRecord.formId,
        formRecord.formProviderInfo.GetFormDataString().length());

    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formRecord.formId, formRecord, formInfo);
    Want newWant(want);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formRecord.formId);
    newWant.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);

    int32_t error = remoteFormRender->RenderForm(formInfo, newWant, FormSupplyCallback::GetInstance());
    FormRecordReport::GetInstance().IncreaseUpdateTimes(formRecord.formId, HiSysEventPointType::TYPE_DAILY_REFRESH);
    if (!formRecord.isVisible) {
        FormRecordReport::GetInstance().IncreaseUpdateTimes(
            formRecord.formId, HiSysEventPointType::TYPE_INVISIBLE_UPDATE);
    }
    if (error != ERR_OK) {
        HILOG_ERROR("StopRenderingForm fail formId: %{public}" PRId64 " error: %{public}d", formRecord.formId, error);
        RemoveConnection(connectId);
        FormStatusMgr::GetInstance().CancelFormEventTimeout(formRecord.formId, eventId);
        FormStatusMgr::GetInstance().PostFormEvent(formRecord.formId, FormFsmEvent::RENDER_FORM_FAIL);
    }

    HILOG_DEBUG("end");
}

void FormStatusTaskMgr::RemoveConnection(int32_t connectId)
{
    auto formSupplyCallback = FormSupplyCallback::GetInstance();
    if (formSupplyCallback == nullptr) {
        HILOG_ERROR("formSupplyCallback is nullptr.");
        return;
    }
    formSupplyCallback->RemoveConnection(connectId);
}

void FormStatusTaskMgr::RestoreFormRecycledStatus(const FormRecord &formRecord, const sptr<IRemoteObject> &remoteObject)
{
    if (!FormDataMgr::GetInstance().IsExpectRecycled(formRecord.formId)) {
        return;
    }
    HILOG_INFO("form is expect recycled, formId: %{public}" PRId64, formRecord.formId);
    auto recycleForm = [formRecord, remoteObject]() {
        if (!FormDataMgr::GetInstance().IsExpectRecycled(formRecord.formId)) {
            HILOG_WARN("form not need recycle, formId: %{public}" PRId64, formRecord.formId);
            const std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formRecord.formId);
            FormStatusMgr::GetInstance().CancelFormEventTimeout(formRecord.formId, eventId);
            FormStatusMgr::GetInstance().PostFormEvent(formRecord.formId, FormFsmEvent::RECYCLE_DATA_FAIL);
            return;
        }
        std::vector<FormHostRecord> formHostRecord;
        FormDataMgr::GetInstance().GetFormHostRecord(formRecord.formId, formHostRecord);
        auto formUserUids = formRecord.formUserUids;
        for (auto &hostRecord : formHostRecord) {
            auto iter = std::find(formUserUids.begin(), formUserUids.end(), hostRecord.GetCallerUid());
            if (iter != formUserUids.end()) {
                FormStatusTaskMgr::GetInstance().RecycleForm(formRecord.formId, hostRecord.GetFormHostClient(),
                    remoteObject);
            }
        }
    };
    FormStatusMgr::GetInstance().PostFormEvent(formRecord.formId, FormFsmEvent::RECYCLE_DATA, recycleForm);
}
}  // namespace AppExecFwk
}  // namespace OHOS