/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formtaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_distributed_client.h"
#include "form_task_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormTaskMgr formTaskMgr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.PostAcquireTask(formId, want, remoteObject);
    std::string remoteDeviceId(data, size);
    formTaskMgr.PostShareAcquireTask(formId, remoteDeviceId, want, remoteObject);
    formTaskMgr.PostDeleteTask(formId, want, remoteObject);
    formTaskMgr.PostRefreshTask(formId, want, remoteObject);
    formTaskMgr.PostCastTempTask(formId, want, remoteObject);
    FormRecord record;
    formTaskMgr.PostAcquireTaskToHost(formId, record, remoteObject);
    formTaskMgr.PostUpdateTaskToHost(formId, record, remoteObject);
    sptr<IRemoteObject> remoteHost = nullptr;
    formTaskMgr.PostHostDiedTask(remoteHost);
    std::vector<int64_t> formEvent;
    formEvent.emplace_back(formId);
    int32_t formVisibleType = static_cast<int32_t>(GetU32Data(data));
    formTaskMgr.PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    std::set<int64_t> formIds;
    formIds.insert(formId);
    formTaskMgr.PostProviderBatchDeleteTask(formIds, want, remoteObject);
    std::string message(data, size);
    formTaskMgr.PostFormEventTask(formId, message, want, remoteObject);
    Want wantArg;
    std::string provider(data, size);
    formTaskMgr.PostAcquireStateTask(wantArg, provider, want, remoteObject);
    std::vector<int64_t> formIdes;
    formIdes.emplace_back(formId);
    formTaskMgr.PostUninstallTaskToHost(formIdes, remoteObject);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want wants;
    formTaskMgr.PostAcquireStateTaskToHost(state, wants, remoteObject);
    int64_t formShareRequestCode = static_cast<int64_t>(GetU32Data(data));
    int32_t result = static_cast<int32_t>(GetU32Data(data));
    formTaskMgr.PostFormShareSendResponse(formShareRequestCode, result);
    formTaskMgr.AcquireProviderFormInfo(formId, want, remoteObject);
    formTaskMgr.AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    formTaskMgr.NotifyFormDelete(formId, want, remoteObject);
    formTaskMgr.NotifyFormUpdate(formId, want, remoteObject);
    formTaskMgr.EventNotify(formEvent, formVisibleType, want, remoteObject);
    formTaskMgr.NotifyCastTemp(formId, want, remoteObject);
    formTaskMgr.AcquireTaskToHost(formId, record, remoteObject);
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    formTaskMgr.HostDied(remoteObject);
    formTaskMgr.ProviderBatchDelete(formIds, want, remoteObject);
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    formTaskMgr.AcquireState(wantArg, provider, want, remoteObject);
    formTaskMgr.FormUninstall(formIdes, remoteObject);
    formTaskMgr.AcquireStateBack(state, wants, remoteObject);
    formTaskMgr.FormShareSendResponse(formShareRequestCode, result);
    FormDistributedClient formDistributedClient;
    formDistributedClient.GetDmsServiceProxy();
    sptr<IRemoteObject> dmsProxy = nullptr;
    formDistributedClient.SetDmsProxy(dmsProxy);
    FormShareInfo formShareInfo;
    return formDistributedClient.ShareForm(remoteDeviceId, formShareInfo);
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

