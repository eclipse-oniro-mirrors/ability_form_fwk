/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>
#include "form_constants.h"
#include "form_provider_data.h"

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_provider_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected
#include "securec.h"
#include "ffrt.h"

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_STR_LEN = 256;

void DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);
    FormProviderRefreshImpl formProviderRefresh;

    RefreshData refreshData;
    refreshData.formId = fdp.ConsumeIntegral<int64_t>();
    refreshData.callingUid = fdp.ConsumeIntegral<int32_t>();
    refreshData.nextTime = fdp.ConsumeIntegral<int32_t>();

    FormRecord record;
    record.formId = refreshData.formId;
    record.bundleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    refreshData.record = record;

    Want want;
    want.SetParam(Constants::KEY_IS_TIMER, fdp.ConsumeBool());
    want.SetParam(Constants::KEY_TIMER_REFRESH, fdp.ConsumeBool());
    want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, fdp.ConsumeIntegral<int32_t>());
    refreshData.want = want;

    std::string jsonDataString = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    FormProviderData providerData(jsonDataString);
    refreshData.providerData = providerData;

    formProviderRefresh.RefreshFormRequest(refreshData);
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < 1) {
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
