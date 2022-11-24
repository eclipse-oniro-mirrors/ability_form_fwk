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

#include "formhostrecord_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "form_host_record.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormHostRecord formHostRecord;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    formHostRecord.AddForm(formId);
    formHostRecord.DelForm(formId);
    formHostRecord.Contains(formId);
    bool flag = *data % ENABLE;
    formHostRecord.SetEnableRefresh(formId, flag);
    formHostRecord.IsEnableRefresh(formId);
    bool enable = *data % ENABLE;
    formHostRecord.SetEnableUpdate(formId, enable);
    formHostRecord.IsEnableUpdate(formId);
    formHostRecord.SetNeedRefresh(formId, flag);
    formHostRecord.IsNeedRefresh(formId);
    formHostRecord.GetFormHostClient();
    int64_t id = static_cast<int64_t>(GetU32Data(data));
    FormRecord record;
    formHostRecord.OnAcquire(id, record);
    formHostRecord.OnUpdate(id, record);
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    formHostRecord.OnFormUninstalled(formIds);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    formHostRecord.OnAcquireState(state, want);
    formHostRecord.CleanResource();
    int callerUid = static_cast<int>(GetU32Data(data));
    formHostRecord.SetCallerUid(callerUid);
    sptr<IRemoteObject> formHostClient = nullptr;
    formHostRecord.SetFormHostClient(formHostClient);
    std::shared_ptr<FormHostCallback> formHostCallback = nullptr;
    formHostRecord.SetCallback(formHostCallback);
    formHostRecord.GetDeathRecipient();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formHostRecord.SetDeathRecipient(deathRecipient);
    formHostRecord.AddDeathRecipient(deathRecipient);
    FormItemInfo info;
    sptr<IRemoteObject> callback = nullptr;
    int callingUid = static_cast<int>(GetU32Data(data));
    formHostRecord.CreateRecord(info, callback, callingUid);
    formHostRecord.GetHostBundleName();
    std::string hostBundleName(data, size);
    formHostRecord.SetHostBundleName(hostBundleName);
    return formHostRecord.IsEmpty();
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

