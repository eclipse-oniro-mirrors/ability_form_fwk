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

#include "formproviderinfo_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ffrt.h"
#include "form_provider_info.h"
#include "securec.h"

// Interpose ffrt_queue_submit_h so no ffrt task is ever enqueued. Enqueuing
// tasks spawns ffrt CPU workers whose threads still run when ffrt's static
// CPUWorkerGroup is torn down at exit (heap-use-after-free).
extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

// Interpose WatchParameter so the memory-watermark watcher never arms. The
// param-service callback creates an ffrt queue during exit, racing with ffrt's
// static QueueMonitor teardown (heap-use-after-free).
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

// Sanitize fuzz bytes to pure ASCII so json::dump() doesn't abort on invalid UTF-8.
std::string GenerateSafeString(FuzzedDataProvider *fdp)
{
    std::string raw = fdp->ConsumeRandomLengthString(64);
    std::string result;
    for (char c : raw) {
        if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' || c == ':') {
            result += c;
        }
    }
    return result.empty() ? "default" : result;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FormProviderInfo formProviderInfo;
    std::string dataString = GenerateSafeString(fdp);
    formProviderInfo.SetFormDataString(dataString);
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    formProviderInfo.SetImageDataMap(imageDataMap);
    formProviderInfo.GetImageDataMap();
    nlohmann::json addJsonData;
    std::string key1 = GenerateSafeString(fdp);
    std::string value1 = GenerateSafeString(fdp);
    std::string key2 = GenerateSafeString(fdp);
    std::string value2 = GenerateSafeString(fdp);
    std::string jsonStr = "{\"" + key1 + "\" : \"" + value1 + "\", \"" + key2 + "\" : \"" + value2 +"\"}";
    addJsonData = nlohmann::json::parse(jsonStr, nullptr, false);
    formProviderInfo.MergeData(addJsonData);
    formProviderInfo.NeedCache();
    Parcel parcel;
    return formProviderInfo.Marshalling(parcel);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

