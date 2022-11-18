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

#include "formmgradaptertwo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr_adapter.h"
#undef private
#undef protected
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
    FormMgrAdapter formMgrAdapter;
    Want want;
    formMgrAdapter.RequestPublishFormToHost(want);
    bool withFormBindingData = *data % ENABLE;
    std::unique_ptr<FormProviderData> formBindingData = nullptr;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    formMgrAdapter.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    Want formProviderWant;
    formMgrAdapter.CheckAddRequestPublishForm(want, formProviderWant);
    FormItemInfo formItemInfo;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo);
    int64_t nextTime = static_cast<int64_t>(GetU32Data(data));
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formMgrAdapter.SetNextRefreshTimeLocked(formId, nextTime, userId);
    std::string bundleName(data, size);
    formMgrAdapter.IsUpdateValid(formId, bundleName);
    std::vector<int64_t> formIDs;
    formIDs.emplace_back(formId);
    formMgrAdapter.EnableUpdateForm(formIDs, callerToken);
    formMgrAdapter.DisableUpdateForm(formIDs, callerToken);
    formMgrAdapter.MessageEvent(formId, want, callerToken);
    bool flag = *data % ENABLE;
    bool isOnlyEnableUpdate = *data % ENABLE;
    formMgrAdapter.HandleUpdateFormFlag(formIDs, callerToken, flag, isOnlyEnableUpdate);
    FormRecord record;
    formMgrAdapter.IsFormCached(record);
    return true;
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
    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = reinterpret_cast<char *>(malloc(size + 1));
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

