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

#include "form_host/form_host_callback.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_host_interface.h"
#include "form_render/form_render_mgr.h"
#include "form_host/form_host_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Request to give back a Form.
 * @param formId The Id of the forms to create.
 * @param record Form record.
 * @param callerToken Caller ability token.
 */
void FormHostCallback::OnAcquired(const int64_t formId, const FormRecord& record,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("FormHostCallback OnAcquired, formId:%{public}" PRId64 "", formId);
    FormHostTaskMgr::GetInstance().PostAcquireTaskToHost(formId, record, callerToken);
}

/**
* @brief Form is updated.
* @param formId The Id of the form to update.
* @param record Form record.
* @param callerToken Caller ability token.
*/
void FormHostCallback::OnUpdate(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("start");

    // check formId
    if (formId < 0) {
        HILOG_ERROR("OnUpdate invalid param, formId:%{public}" PRId64 ".", formId);
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }

    // post updateTask to host
    FormHostTaskMgr::GetInstance().PostUpdateTaskToHost(formId, record, callerToken);
}

/**
 * @brief Form provider is uninstalled
 * @param formIds The Id list of the forms.
 * @param callerToken Caller ability token.
 */
void FormHostCallback::OnUninstall(std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken)
{
    // check formId
    if (formIds.empty()) {
        HILOG_ERROR("OnUninstall invalid param, formIds is empty");
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    // post updateTask to host
    FormHostTaskMgr::GetInstance().PostUninstallTaskToHost(formIds, callerToken);
}

void FormHostCallback::OnAcquireFormData(const AAFwk::WantParams &wantParams, int64_t requestCode,
                                         const sptr<IRemoteObject> &callerToken)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    // post updateTask to host
    FormHostTaskMgr::GetInstance().PostAcquireDataTaskToHost(wantParams, requestCode, callerToken);
}

/**
 * @brief Send form state message to form host.
 * @param state The form state.
 * @param want The want of onAcquireFormState.
 * @param callerToken Caller ability token.
 */
void FormHostCallback::OnAcquireState(AppExecFwk::FormState state, const AAFwk::Want &want,
                                      const sptr<IRemoteObject> &callerToken)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    // post updateTask to host
    FormHostTaskMgr::GetInstance().PostAcquireStateTaskToHost(state, want, callerToken);
}

/**
 * @brief Send recycle form message to form host.
 * @param formIds The Id list of forms.
 * @param want The want of forms to be recycled.
 * @param callerToken Caller ability token.
 */
void FormHostCallback::OnRecycleForms(
    const std::vector<int64_t> &formIds, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    FormRenderMgr::GetInstance().RecycleForms(formIds, want, callerToken);
}

void FormHostCallback::OnEnableForms(
    const std::vector<int64_t> &formIds, const bool enable, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("size:%{public}zu, enable:%{public}d", formIds.size(), enable);
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    // post enableFormsTask to host
    FormHostTaskMgr::GetInstance().PostEnableFormsTaskToHost(formIds, enable, callerToken);
}

void FormHostCallback::OnLockForms(const std::vector<int64_t> &formIds,
    const bool lock, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("size:%{public}zu, lock:%{public}d", formIds.size(), lock);
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    // post enableFormsTask to host
    FormHostTaskMgr::GetInstance().PostLockFormsTaskToHost(formIds, lock, callerToken);
}

void FormHostCallback::OnDueControlForms(const std::vector<int64_t> &formIds, const bool isDisablePolicy,
    const bool isControl, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("size:%{public}zu, isDisablePolicy:%{public}d, isControl:%{public}d",
        formIds.size(), isDisablePolicy, isControl);
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return;
    }
    FormHostTaskMgr::GetInstance().PostDueControlFormsTaskToHost(formIds, isDisablePolicy, isControl, callerToken);
}
}  // namespace AppExecFwk
}  // namespace OHOS
