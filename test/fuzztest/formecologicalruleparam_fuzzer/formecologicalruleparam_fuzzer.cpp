/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "formecologicalruleparam_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_ecological_rule_param.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_NUM = 1000;
constexpr int32_t MIN_NUM = 0;
constexpr size_t MAX_LENGTH = 5;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FormErmsCallerInfo formErmsCallerInfo;
    formErmsCallerInfo.uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formErmsCallerInfo.pid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formErmsCallerInfo.packageName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formErmsCallerInfo.callerAppType = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formErmsCallerInfo.targetAppType = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    formErmsCallerInfo.ToString();
    Parcel parcel;
    formErmsCallerInfo.ReadFromParcel(parcel);
    bool isTrue = fdp->ConsumeBool();
    if (formErmsCallerInfo.uid == formErmsCallerInfo.pid && isTrue) {
        formErmsCallerInfo.Unmarshalling(parcel);
        formErmsCallerInfo.Marshalling(parcel);
        formErmsCallerInfo.Unmarshalling(parcel);
    }
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

