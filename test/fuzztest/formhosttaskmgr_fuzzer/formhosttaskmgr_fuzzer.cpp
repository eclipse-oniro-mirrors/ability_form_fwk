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

#include "formhosttaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_host/form_host_task_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
void DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormHostTaskMgr formTaskMgr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    sptr<IRemoteObject> remoteObject = nullptr;
    FormRecord record;
    formTaskMgr.PostAcquireTaskToHost(formId, record, remoteObject);
    formTaskMgr.PostUpdateTaskToHost(formId, record, remoteObject);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    formTaskMgr.PostUninstallTaskToHost(formIds, remoteObject);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want wants;
    formTaskMgr.PostAcquireStateTaskToHost(state, wants, remoteObject);
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    formTaskMgr.PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    formTaskMgr.PostEnableFormsTaskToHost(formIds, false, remoteObject);
    formTaskMgr.PostLockFormsTaskToHost(formIds, false, remoteObject);
    formTaskMgr.PostFrsDiedTaskToHost(remoteObject);
    sptr<IRemoteObject> remoteHost = nullptr;
    formTaskMgr.PostHostDiedTask(remoteHost);
    formTaskMgr.AcquireTaskToHost(formId, record, remoteObject);
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    formTaskMgr.FormUninstall(formIds, remoteObject);
    formTaskMgr.AcquireStateBack(state, wants, remoteObject);
    formTaskMgr.AcquireFormDataBack(wantParams, requestCode, remoteObject);
    formTaskMgr.EnableFormsTaskToHost(formIds, false, remoteObject);
    formTaskMgr.LockFormsTaskToHost(formIds, false, remoteObject);
    formTaskMgr.FrsDiedTaskToHost(remoteObject);
    formTaskMgr.HostDied(remoteHost);

    int32_t errorCode = static_cast<int32_t>(GetU32Data(data));
    formTaskMgr.PostConnectFRSFailedTaskToHost(formId, errorCode);
    formTaskMgr.ConnectFRSFailedTaskToHost(formId, errorCode);

    bool isDisablePolicy = (formId % 2 == 0);
    bool isControl = (formId % 3 == 0);
    formTaskMgr.PostDueControlFormsTaskToHost(formIds, isDisablePolicy, isControl, remoteObject);
    formTaskMgr.DueControlFormsTaskToHost(formIds, isDisablePolicy, isControl, remoteObject);

    formTaskMgr.PostCheckFormsTaskToHost(formIds, remoteObject);
    formTaskMgr.CheckFormsTaskToHost(formIds, remoteObject);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

