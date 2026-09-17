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

#include <cctype>
#include "formproviderdata_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_provider_data.h"
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

constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MAX_SAFE_STRING_LENGTH = 64;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

// Sanitize fuzz bytes to pure ASCII so json::dump() doesn't abort on invalid UTF-8.
std::string GenerateSafeString(const char* data, size_t size)
{
    std::string result;
    for (size_t i = 0; i < size && i < MAX_SAFE_STRING_LENGTH; i++) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' || c == ':') {
            result += static_cast<char>(c);
        }
    }
    return result.empty() ? "default" : result;
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormProviderData formProviderData;
    std::string picName(data, size);
    const std::shared_ptr<char> datas = nullptr;
    int32_t sizes = static_cast<int32_t>(GetU32Data(data));
    formProviderData.AddImageData(picName, datas, sizes);
    int fd = static_cast<int>(GetU32Data(data));
    formProviderData.AddImageData(picName, fd);
    formProviderData.ParseImagesData();
    formProviderData.RemoveImageData(picName);
    std::string jsonDataString = GenerateSafeString(data, size);
    formProviderData.SetDataString(jsonDataString);
    nlohmann::json addJsonData;
    formProviderData.MergeData(addJsonData);
    formProviderData.GetImageDataMap();
    int32_t imageDataState = static_cast<int32_t>(GetU32Data(data));
    formProviderData.SetImageDataState(imageDataState);
    Parcel parcel;
    formProviderData.ReadFromParcel(parcel);
    formProviderData.Marshalling(parcel);
    formProviderData.Unmarshalling(parcel);
    formProviderData.ClearData();
    formProviderData.NeedCache();
    formProviderData.WriteImageDataToParcel(parcel, picName, datas, sizes);
    formProviderData.ConvertRawImageData();
    return formProviderData.GetDataString() == "aa";
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

