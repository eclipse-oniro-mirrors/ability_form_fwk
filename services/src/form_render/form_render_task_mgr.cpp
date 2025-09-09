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

#include "form_render/form_render_task_mgr.h"

#include "form_render_interface.h"
#include "form_js_info.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "form_render/form_render_queue.h"
#include "form_event_report.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
FormRenderTaskMgr::FormRenderTaskMgr() {}

FormRenderTaskMgr::~FormRenderTaskMgr() {}

void FormRenderTaskMgr::PostUpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
    const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    auto updateFormSize = [formId, width, height, borderWidth, uid, remoteObject]() {
        FormRenderTaskMgr::GetInstance().UpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    };
    FormRenderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, updateFormSize);
    HILOG_DEBUG("end");
}

void FormRenderTaskMgr::PostOnUnlock(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");

    auto task = [remoteObject]() {
        FormRenderTaskMgr::GetInstance().OnUnlock(remoteObject);
    };
    FormRenderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, task);
    HILOG_DEBUG("end");
}

void FormRenderTaskMgr::PostSetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("call");

    auto task = [formId, isVisible, remoteObject]() {
        FormRenderTaskMgr::GetInstance().SetVisibleChange(formId, isVisible, remoteObject);
    };
    FormRenderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, task);
    HILOG_INFO("start task formId: %{public}" PRId64 " isVisible: %{public}d", formId, isVisible);
}

void FormRenderTaskMgr::PostReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin");

    auto reloadForm = [forms = std::forward<decltype(formRecords)>(formRecords), want, remoteObject]() {
        FormRenderTaskMgr::GetInstance().ReloadForm(std::move(forms), want, remoteObject);
    };
    FormRenderQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, reloadForm);
    HILOG_INFO("end");
}

void FormRenderTaskMgr::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
    const std::string &uid, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("start");

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    int32_t error = remoteFormRender->UpdateFormSize(formId, width, height, borderWidth, uid);
    if (error != ERR_OK) {
        HILOG_ERROR("fail Update FormSize");
        return;
    }

    HILOG_DEBUG("end");
}

void FormRenderTaskMgr::OnUnlock(const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("begin");

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }
    int32_t error = remoteFormRender->OnUnlock();
    if (error != ERR_OK) {
        HILOG_ERROR("fail");
        return;
    }
    HILOG_DEBUG("end");
}

void FormRenderTaskMgr::SetVisibleChange(int64_t formId, bool isVisible, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin");

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("form %{public}" PRId64 " not exist", formId);
        return;
    }

    Want want;
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(formRecord.providerUserId) + formRecord.bundleName);

    int32_t error = remoteFormRender->SetVisibleChange(formId, isVisible, want);
    if (error != ERR_OK) {
        HILOG_ERROR("fail");
        return;
    }
    HILOG_INFO("end");
}

void FormRenderTaskMgr::ReloadForm(const std::vector<FormRecord> &&formRecords, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("begin");

    sptr<IFormRender> remoteFormRender = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRender == nullptr) {
        HILOG_ERROR("get formRenderProxy failed");
        return;
    }

    std::string bundleName = want.GetStringParam(Constants::PARAM_BUNDLE_NAME_KEY);
    if (bundleName.empty()) {
        HILOG_ERROR("GetBundleName failed");
        return;
    }

    std::vector<FormJsInfo> formJsInfos;
    for (const auto &formRecord : formRecords) {
        FormJsInfo formInfo;
        FormDataMgr::GetInstance().CreateFormJsInfo(formRecord.formId, formRecord, formInfo);
        formJsInfos.emplace_back(formInfo);
    }

    int32_t error = remoteFormRender->ReloadForm(std::move(formJsInfos), want);
    if (error != ERR_OK) {
        HILOG_ERROR("fail reload form");
        FormEventReport::SendFormFailedEvent(FormEventName::RELOAD_FORM_FAILED,
            0,
            bundleName,
            "",
            static_cast<int32_t>(ReloadFormErrorType::RELOAD_FORM_FRS_DEAD),
            error);
        return;
    }
    RestoreFormsRecycledStatus(std::move(formRecords));

    HILOG_INFO("end");
}

void FormRenderTaskMgr::RestoreFormsRecycledStatus(const std::vector<FormRecord> &&formRecords)
{
    int32_t callingUid = 0;
    std::vector<int64_t> recycleForms;
    for (const auto &formRecord : formRecords) {
        if (FormDataMgr::GetInstance().IsExpectRecycled(formRecord.formId)) {
            HILOG_INFO("form is expect recycled, formId: %{public}" PRId64, formRecord.formId);
            recycleForms.emplace_back(formRecord.formId);
            if (!formRecord.formUserUids.empty() && !callingUid) {
                callingUid = *formRecord.formUserUids.begin();
            }
        }
    }

    FormDataMgr::GetInstance().RecycleForms(recycleForms, callingUid, Want());
}
} // namespace AppExecFwk
} // namespace OHOS