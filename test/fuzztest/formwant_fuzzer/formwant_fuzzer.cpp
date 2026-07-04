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

#include "formwant_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_want.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeIntegral<int32_t>());
    want.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // FormWant default constructor
    FormWant formWant;

    // Set some params to populate
    formWant.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeIntegral<int32_t>());
    formWant.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeBool());

    // FilterInternalParams (static)
    Want sourceWant = GenerateWant(fdp);
    // Add some internal params to test filtering
    sourceWant.SetParam(Constants::FORM_CONNECT_ID, fdp->ConsumeIntegral<int32_t>());
    sourceWant.SetParam(Constants::ACQUIRE_TYPE, fdp->ConsumeIntegral<int32_t>());
    Want filteredWant = FormWant::FilterInternalParams(sourceWant);

    // GetFilteredWant (member)
    formWant.GetFilteredWant();

    // MergeFrom
    Want mergeSource = GenerateWant(fdp);
    formWant.MergeFrom(mergeSource);

    // MergeWantParams (static)
    Want mergeTarget = GenerateWant(fdp);
    Want mergeSource2 = GenerateWant(fdp);
    FormWant::MergeWantParams(mergeTarget, mergeSource2);

    // ExtractHostParamsToWant
    Want hostTarget;
    formWant.ExtractHostParamsToWant(hostTarget);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
