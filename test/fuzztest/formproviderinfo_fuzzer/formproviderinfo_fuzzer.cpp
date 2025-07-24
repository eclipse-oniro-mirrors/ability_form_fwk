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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "form_provider_info.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FormProviderInfo formProviderInfo;
    std::string dataString = fdp->ConsumeRandomLengthString();
    formProviderInfo.SetFormDataString(dataString);
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    formProviderInfo.SetImageDataMap(imageDataMap);
    formProviderInfo.GetImageDataMap();
    nlohmann::json addJsonData;
    std::string key1 = fdp->ConsumeRandomLengthString();
    std::string value1 = fdp->ConsumeRandomLengthString();
    std::string key2 = fdp->ConsumeRandomLengthString();
    std::string value2 = fdp->ConsumeRandomLengthString();
    std::string jsonStr = "{\"" + key1 + "\" : " + value1 + ", \"" + key2 + "\" : " + value2 +"}";
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

