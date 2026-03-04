/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "formproviderrefreshimpl_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_provider_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

void DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormProviderRefreshImpl formProviderRefresh;

    RefreshData refreshData;
    refreshData.formId = static_cast<int64_t>(GetU32Data(data));
    refreshData.callingUid = static_cast<int32_t>(GetU32Data(data));
    refreshData.nextTime = static_cast<int32_t>(GetU32Data(data));

    FormRecord record;
    record.formId = refreshData.formId;
    record.bundleName = std::string(data, size);
    refreshData.record = record;

    Want want;
    want.SetParam("test_param", std::string(data, size));
    refreshData.want = want;

    FormProviderData providerData;
    refreshData.providerData = providerData;

    formProviderRefresh.RefreshFormRequest(refreshData);
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
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
