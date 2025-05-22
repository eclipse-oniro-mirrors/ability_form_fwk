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
#include "form_mgr/form_mgr_queue.h"
#include "data_center/form_record/form_record_report.h"
#include "form_provider/form_supply_callback.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_cache_mgr.h"
 
namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_TASK_DELAY_TIME = 20; // ms
constexpr int32_t FORM_BUILD_DELAY_TIME = 2000; // ms
}
FormStatusTaskMgr::FormStatusTaskMgr() {}

FormStatusTaskMgr::~FormStatusTaskMgr() {}

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

    auto delayTime = want.GetIntParam(Constants::FORM_DELAY_TIME_OF_RECYCLE, FORM_TASK_DELAY_TIME);
    for (const int64_t formId : formIds) {
        auto recycleForm = [formId, remoteObjectOfHost, remoteObjectOfRender]() {
            FormStatusTaskMgr::GetInstance().RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
        };
        {
            std::lock_guard<std::mutex> lock(formRecoverTimesMutex_);
            formLastRecoverTimes.erase(formId);
        }
        FormMgrQueue::GetInstance().ScheduleDelayTask(
            std::make_pair((int64_t)TaskType::RECYCLE_FORM, formId), delayTime, recycleForm);
    }
    HILOG_DEBUG("end");
}

/**
 * @brief Post recover forms.
 * @param formIds the Ids of forms to be recycled.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormStatusTaskMgr::PostRecoverForm(const FormRecord &record, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    auto formId = record.formId;
    auto recoverForm = [record, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().RecoverForm(record, want, remoteObject);
    };
    {
        std::lock_guard<std::mutex> lock(formRecoverTimesMutex_);
        formLastRecoverTimes[formId] = FormUtil::GetCurrentMillisecond();
    }
    auto hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    FormCommand recoverCommand{
        formId,
        std::make_pair(TaskCommandType::RECOVER_FORM, formId),
        FORM_TASK_DELAY_TIME,
        recoverForm};
    FormStatusQueue::GetInstance().PostFormStatusTask(recoverCommand, hostToken);
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
    HILOG_INFO("begin formId: %{public}" PRId64, formId);
 
    auto deleterenderForm = [formId, compId, uid, remoteObject]() {
        FormStatusTaskMgr::GetInstance().ReleaseRenderer(formId, compId, uid, remoteObject);
    };
    {
        std::lock_guard<std::mutex> lock(formRecoverTimesMutex_);
        formLastRecoverTimes.erase(formId);
    }
    if (!isDynamic) {
        FormCommand deleteCommand{
            formId,
            std::make_pair(TaskCommandType::DELETE_FORM, formId),
            FORM_TASK_DELAY_TIME,
            deleterenderForm};
        FormStatusQueue::GetInstance().PostFormDeleteTask(deleteCommand, compId);
    } else {
        FormCommand releaseRenderCommand{
            formId,
            std::make_pair(TaskCommandType::RECYCLE_FORM, formId),
            FORM_TASK_DELAY_TIME,
            deleterenderForm};
        FormStatusQueue::GetInstance().PostFormStatusTask(releaseRenderCommand);
    }
    HILOG_INFO("end formId: %{public}" PRId64, formId);
}

/**
 * @brief Post render form.
 * @param formRecord The form record.
 * @param want The want of the request.
 * @param remoteObject Form render proxy object.
 */
void FormStatusTaskMgr::PostRenderForm(const FormRecord &formRecord, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    auto renderType = want.GetIntParam(Constants::FORM_UPDATE_TYPE_KEY,
        Constants::ADD_FORM_UPDATE_FORM);
    if (renderType != Constants::ADAPTER_UPDATE_FORM
        || FormDataMgr::GetInstance().GetFormCanUpdate(formRecord.formId)) {
        FormStatusTaskMgr::GetInstance().InnerPostRenderForm(formRecord, want, remoteObject);
        return;
    }
    auto task = [formRecord, want, remoteObject]() {
        FormRecord newRecord(formRecord);
        std::string cacheData;
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
        bool hasCacheData = FormCacheMgr::GetInstance().GetData(formRecord.formId, cacheData, imageDataMap);
        if (hasCacheData) {
            newRecord.formProviderInfo.SetFormDataString(cacheData);
            newRecord.formProviderInfo.SetImageDataMap(imageDataMap);
        }
        FormStatusTaskMgr::GetInstance().InnerPostRenderForm(newRecord, want, remoteObject);
    };
    FormRenderMgr::GetInstance().AddPostRenderFormTask(formRecord.formId, task);
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
    HILOG_INFO("call");

    auto formId = formRecord.formId;
    auto deleterenderForm = [formRecord, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().StopRenderingForm(formRecord, want, remoteObject);
    };
    {
        std::lock_guard<std::mutex> lock(formRecoverTimesMutex_);
        formLastRecoverTimes.erase(formId);
    }
    FormCommand deleteCommand{
        formId,
        std::make_pair(TaskCommandType::DELETE_FORM, formId),
        FORM_TASK_DELAY_TIME,
        deleterenderForm};
    std::string compId = want.GetStringParam(Constants::FORM_RENDER_COMP_ID);
    FormStatusQueue::GetInstance().PostFormDeleteTask(deleteCommand, compId);
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
    if (formRecord.recycleStatus != RecycleStatus::RECYCLABLE) {
        HILOG_ERROR("form %{public}" PRId64 " not RECYCLABLE", formId);
        return;
    }

    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(formRecord.providerUserId) + formRecord.bundleName);
    want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, remoteObjectOfHost);
    int32_t error = remoteFormRender->RecycleForm(formId, want);
    if (error != ERR_OK) {
        HILOG_ERROR("RecycleForm fail formId: %{public}" PRId64 " error: %{public}d", formId, error);
        return;
    }
}

void FormStatusTaskMgr::RecoverForm(const FormRecord &record, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formJsInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(record.formId, record, formJsInfo);

    int32_t error = remoteFormRender->RecoverForm(formJsInfo, want);
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail recover form");
        FormStatusMgr::GetInstance().ResetFormStatus(record.formId);
        return;
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

    int32_t error = remoteFormDeleteRender->ReleaseRenderer(formId, compId, uid);
    if (error != ERR_OK) {
        HILOG_ERROR("fail release form renderer");
        return;
    }
    HILOG_INFO("end formId: %{public}" PRId64, formId);
}

void FormStatusTaskMgr::InnerPostRenderForm(const FormRecord &formRecord, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("PostRenderForm");

    auto renderForm = [formRecord, want, remoteObject]() {
        FormStatusTaskMgr::GetInstance().RenderForm(formRecord, want, remoteObject);
    };
    
    int64_t formId = formRecord.formId;
    int64_t lastRecoverTime = 0;
    {
        std::lock_guard<std::mutex> lock(formRecoverTimesMutex_);
        if (formLastRecoverTimes.find(formId) != formLastRecoverTimes.end()) {
            lastRecoverTime = formLastRecoverTimes[formId];
            formLastRecoverTimes.erase(formId);
        }
    }
    auto hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    int32_t recoverInterval = (int32_t) (FormUtil::GetCurrentMillisecond() - lastRecoverTime);
    if (lastRecoverTime <= 0 || recoverInterval > FORM_BUILD_DELAY_TIME) {
        FormCommand renderCommand{
            formId,
            std::make_pair(TaskCommandType::RENDER_FORM, formId),
            FORM_TASK_DELAY_TIME,
            renderForm};
        FormStatusQueue::GetInstance().PostFormStatusTask(renderCommand, hostToken);
    } else {
        HILOG_INFO("delay render task: %{public}" PRId32 " ms, formId is %{public}" PRId64, recoverInterval, formId);
        int32_t delayTime = FORM_BUILD_DELAY_TIME - recoverInterval;
        delayTime = std::min(delayTime, FORM_BUILD_DELAY_TIME);
        delayTime = std::max(delayTime, FORM_TASK_DELAY_TIME);
        FormCommand renderCommand{
            formId,
            std::make_pair(TaskCommandType::RENDER_FORM, formId),
            delayTime,
            renderForm};
        FormStatusQueue::GetInstance().PostFormStatusTask(renderCommand, hostToken);
    }
    HILOG_DEBUG("end");
}

void FormStatusTaskMgr::StopRenderingForm(
    const FormRecord &formRecord, const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormDeleteRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormDeleteRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formRecord.formId, formRecord, formInfo);
    int32_t error = remoteFormDeleteRender->StopRenderingForm(formInfo, want, FormSupplyCallback::GetInstance());
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail add form renderer");
        return;
    }

    HILOG_INFO("end");
}

void FormStatusTaskMgr::RenderForm(const FormRecord &formRecord, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("render form");
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        RemoveConnection(connectId);
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormJsInfo formInfo;
    FormDataMgr::GetInstance().CreateFormJsInfo(formRecord.formId, formRecord, formInfo);
    int32_t error = remoteFormRender->RenderForm(formInfo, want, FormSupplyCallback::GetInstance());
    FormRecordReport::GetInstance().IncreaseUpdateTimes(formRecord.formId, HiSysEventPointType::TYPE_DAILY_REFRESH);
    if (!formRecord.isVisible) {
        FormRecordReport::GetInstance().IncreaseUpdateTimes(formRecord.formId,
            HiSysEventPointType::TYPE_INVISIBLE_UPDATE);
    }
    if (error != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("fail add form renderer");
        FormStatusMgr::GetInstance().ResetFormStatus(formRecord.formId);
        return;
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
} // namespace AppExecFwk
} // namespace OHOS