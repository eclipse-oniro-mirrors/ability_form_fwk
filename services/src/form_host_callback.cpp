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

#include "form_host_callback.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_host_interface.h"
#include "form_task_mgr.h"
#include "form_render_mgr.h"

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
    FormTaskMgr::GetInstance().PostAcquireTaskToHost(formId, record, callerToken);
}

/**
* @brief Form is updated.
* @param formId The Id of the form to update.
* @param record Form record.
* @param callerToken Caller ability token.
*/
void FormHostCallback::OnUpdate(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s start.", __func__);

    // check formId
    if (formId < 0) {
        HILOG_ERROR("%{public}s: OnUpdate invalid param, formId:%{public}" PRId64 ".", __func__, formId);
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s: callerToken can not be NULL", __func__);
        return;
    }

    // post updateTask to host
    FormTaskMgr::GetInstance().PostUpdateTaskToHost(formId, record, callerToken);
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
        HILOG_ERROR("%{public}s: OnUninstall invalid param, formIds is empty.", __func__);
        return;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s: callerToken can not be NULL", __func__);
        return;
    }
    // post updateTask to host
    FormTaskMgr::GetInstance().PostUninstallTaskToHost(formIds, callerToken);
}

void FormHostCallback::OnAcquireFormData(const AAFwk::WantParams &wantParams, int64_t requestCode,
                                         const sptr<IRemoteObject> &callerToken)
{
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken can not be NULL");
        return;
    }
    // post updateTask to host
    FormTaskMgr::GetInstance().PostAcquireDataTaskToHost(wantParams, requestCode, callerToken);
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
        HILOG_ERROR("%{public}s: callerToken can not be NULL", __func__);
        return;
    }
    // post updateTask to host
    FormTaskMgr::GetInstance().PostAcquireStateTaskToHost(state, want, callerToken);
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
    HILOG_DEBUG("start.");
    if (formIds.empty()) {
        HILOG_ERROR("formIds is empty.");
        return;
    }
    if (callerToken == nullptr) {
        HILOG_ERROR("callerToken can not be NULL");
        return;
    }
    FormRenderMgr::GetInstance().RecycleForms(formIds, want, callerToken);
}
}  // namespace AppExecFwk
}  // namespace OHOS
