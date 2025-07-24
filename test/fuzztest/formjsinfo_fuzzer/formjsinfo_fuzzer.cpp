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

#include "formjsinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "form_js_info.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_NUM = 1000;
constexpr int32_t MIN_NUM = 0;

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FormJsInfo formJsInfo;
    formJsInfo.formId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formJsInfo.formName = fdp->ConsumeRandomLengthString();
    formJsInfo.bundleName = fdp->ConsumeRandomLengthString();
    formJsInfo.abilityName = fdp->ConsumeRandomLengthString();
    formJsInfo.moduleName = fdp->ConsumeRandomLengthString();
    formJsInfo.formTempFlag = fdp->ConsumeRandomLengthString().size() % 2;
    Parcel parcel;
    formJsInfo.Marshalling(parcel);
    formJsInfo.Unmarshalling(parcel);
    formJsInfo.ReadImageData(parcel);
    formJsInfo.ConvertRawImageData();
    return formJsInfo.WriteImageData(parcel);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

