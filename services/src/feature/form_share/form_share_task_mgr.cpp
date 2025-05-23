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

#include "feature/form_share/form_share_task_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_queue.h"
#include "feature/form_share/form_share_mgr.h"

namespace OHOS {
namespace AppExecFwk {
FormShareTaskMgr::FormShareTaskMgr() {}

FormShareTaskMgr::~FormShareTaskMgr() {}

void FormShareTaskMgr::PostShareAcquireTask(int64_t formId, const std::string &remoteDeviceId, const Want &want,
    const sptr<IRemoteObject> &remoteObject)
{
    HILOG_INFO("start");

    auto acquireShareProviderFormInfoFunc = [formId, remoteDeviceId, want, remoteObject]() {
        FormShareTaskMgr::GetInstance().AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    };
    if (!FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, acquireShareProviderFormInfoFunc)) {
        HILOG_ERROR("null serialQueue_");
        int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_SHARE_REQUEST_CODE, 0));
        PostFormShareSendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
    }
    HILOG_INFO("end");
}

void FormShareTaskMgr::PostFormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    HILOG_INFO("start");

    auto formShareSendResponseFunc = [formShareRequestCode, result]() {
        FormShareTaskMgr::GetInstance().FormShareSendResponse(formShareRequestCode, result);
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_TASK_DELAY_TIME, formShareSendResponseFunc);
    HILOG_INFO("end");
}

void FormShareTaskMgr::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    auto formShareMgr = DelayedSingleton<FormShareMgr>::GetInstance();
    if (formShareMgr == nullptr) {
        HILOG_ERROR("null formShareMgr");
        return;
    }
    formShareMgr->AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
}

void FormShareTaskMgr::FormShareSendResponse(int64_t formShareRequestCode, int32_t result)
{
    auto formShareMgr = DelayedSingleton<FormShareMgr>::GetInstance();
    if (formShareMgr == nullptr) {
        HILOG_ERROR("null formShareMgr");
        return;
    }
    formShareMgr->SendResponse(formShareRequestCode, result);
}
} // namespace AppExecFwk
} // namespace OHOS