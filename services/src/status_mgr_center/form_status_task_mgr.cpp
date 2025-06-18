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
#include "status_mgr_center/form_status_queue.h"
#include "status_mgr_center/form_status_mgr.h"
#include "form_mgr/form_mgr_queue.h"
#include "data_center/form_record/form_record_report.h"
#include "form_provider/form_supply_callback.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_cache_mgr.h"

namespace OHOS {
namespace AppExecFwk {
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
        FormStatusTaskMgr::GetInstance().ReleaseRenderer(formId, compId, uid, remoteObject);
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
        RemoveConnection(connectId);
        HILOG_ERROR("fail recover form");
    }
    HILOG_DEBUG("end");
}

void FormStatusTaskMgr::ReleaseRenderer(
    int64_t formId, const std::string &compId, const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin formId: %{public}" PRId64, formId);

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
        HILOG_ERROR("fail release form renderer");
    }
    HILOG_INFO("end formId: %{public}" PRId64, formId);
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
        RemoveConnection(connectId);
        HILOG_ERROR("fail add form renderer");
    }
    HILOG_INFO("end");
}

void FormStatusTaskMgr::RenderForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("render form formId: %{public}" PRId64, formRecord.formId);

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
        RemoveConnection(connectId);
        HILOG_ERROR("fail add form renderer");
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
}  // namespace AppExecFwk
}  // namespace OHOS