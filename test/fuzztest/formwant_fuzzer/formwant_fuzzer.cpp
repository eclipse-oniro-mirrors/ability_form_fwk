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
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = -10000;
constexpr int64_t MAX_LONG_NUM = 10000;
constexpr int64_t MIN_LONG_NUM = -10000;
constexpr double MAX_DOUBLE_NUM = 10000.0;
constexpr double MIN_DOUBLE_NUM = -10000.0;
constexpr float MAX_FLOAT_NUM = 10000.0f;
constexpr float MIN_FLOAT_NUM = -10000.0f;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeIntegral<int32_t>());
    want.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

FormWant GenerateFormWant(FuzzedDataProvider *fdp)
{
    FormWant fw;
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeIntegral<int32_t>());
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeBool());
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeRandomLengthString(MAX_LENGTH));
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));
    return fw;
}

void TestConstructors(FuzzedDataProvider *fdp)
{
    FormWant formWant1;

    FormWant source = GenerateFormWant(fdp);
    FormWant formWant2(source);

    Want want = GenerateWant(fdp);
    FormWant formWant3(want);

    FormWant formWant4;
    formWant4 = source;

    FormWant selfAssign = formWant4;
    formWant4 = std::move(selfAssign);
}

void TestSetParamVariants(FuzzedDataProvider *fdp)
{
    FormWant fw;
    std::string key = fdp->ConsumeRandomLengthString(MAX_LENGTH);

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
               fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM));

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeBool());

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
               fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
               fdp->ConsumeRandomLengthString(MAX_LENGTH));

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
               fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));

    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
               fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));

    sptr<IRemoteObject> remoteObj = nullptr;
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), remoteObj);

    std::string chainKey1 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string chainKey2 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    fw.SetParam(chainKey1, fdp->ConsumeIntegral<int32_t>())
      .SetParam(chainKey2, fdp->ConsumeBool());
}

void TestGetParamVariants(FuzzedDataProvider *fdp)
{
    FormWant fw = GenerateFormWant(fdp);

    std::string intKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t intVal = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);
    fw.SetParam(intKey, intVal);

    std::string longKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int64_t longVal = fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM);
    fw.SetParam(longKey, longVal);

    std::string strKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string strVal = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    fw.SetParam(strKey, strVal);

    std::string boolKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bool boolVal = fdp->ConsumeBool();
    fw.SetParam(boolKey, boolVal);

    std::string doubleKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    double doubleVal = fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM);
    fw.SetParam(doubleKey, doubleVal);

    std::string floatKey = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    float floatVal = fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM);
    fw.SetParam(floatKey, floatVal);

    fw.GetIntParam(intKey, fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM));
    fw.GetIntParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                   fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM));

    fw.GetLongParam(longKey, fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));
    fw.GetLongParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                    fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));

    fw.GetStringParam(strKey);
    fw.GetStringParam(fdp->ConsumeRandomLengthString(MAX_LENGTH));

    fw.GetBoolParam(boolKey, fdp->ConsumeBool());
    fw.GetBoolParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), fdp->ConsumeBool());

    fw.GetDoubleParam(doubleKey, fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));
    fw.GetDoubleParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                      fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));

    fw.GetFloatParam(floatKey, fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));
    fw.GetFloatParam(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                     fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));

    fw.GetRemoteObject(fdp->ConsumeRandomLengthString(MAX_LENGTH));

    fw.HasParameter(intKey);
    fw.HasParameter(fdp->ConsumeRandomLengthString(MAX_LENGTH));

    fw.RemoveParam(intKey);
    fw.HasParameter(intKey);
    fw.RemoveParam(fdp->ConsumeRandomLengthString(MAX_LENGTH));
}

void TestGetWant(FuzzedDataProvider *fdp)
{
    FormWant fw = GenerateFormWant(fdp);

    Want wantCopy = fw.GetWant();
    fw.GetFilteredWant();
}

void TestFilterAndMerge(FuzzedDataProvider *fdp)
{
    Want sourceWant = GenerateWant(fdp);
    sourceWant.SetParam(Constants::FORM_CONNECT_ID, fdp->ConsumeIntegral<int32_t>());
    sourceWant.SetParam(Constants::ACQUIRE_TYPE, fdp->ConsumeIntegral<int32_t>());
    FormWant::FilterInternalParams(sourceWant);

    FormWant fw = GenerateFormWant(fdp);
    Want mergeSource = GenerateWant(fdp);
    fw.MergeFrom(mergeSource);

    Want mergeTarget = GenerateWant(fdp);
    Want mergeSource2 = GenerateWant(fdp);
    FormWant::MergeWantParams(mergeTarget, mergeSource2);

    Want hostTarget;
    fw.ExtractHostParamsToWant(hostTarget);
}

void TestEdgeCases(FuzzedDataProvider *fdp)
{
    FormWant fw;
    fw.SetParam("", fdp->ConsumeIntegral<int32_t>());
    fw.SetParam("", fdp->ConsumeBool());
    fw.SetParam("", fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));
    fw.SetParam("", fdp->ConsumeRandomLengthString(MAX_LENGTH));
    fw.SetParam("", fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));
    fw.SetParam("", fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));

    fw.GetIntParam("", fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM));
    fw.GetLongParam("", fdp->ConsumeIntegralInRange<int64_t>(MIN_LONG_NUM, MAX_LONG_NUM));
    fw.GetStringParam("");
    fw.GetBoolParam("", fdp->ConsumeBool());
    fw.GetDoubleParam("", fdp->ConsumeFloatingPointInRange<double>(MIN_DOUBLE_NUM, MAX_DOUBLE_NUM));
    fw.GetFloatParam("", fdp->ConsumeFloatingPointInRange<float>(MIN_FLOAT_NUM, MAX_FLOAT_NUM));
    fw.GetRemoteObject("");
    fw.HasParameter("");
    fw.RemoveParam("");

    FormWant fw2 = GenerateFormWant(fdp);
    FormWant selfAssign2 = fw2;
    fw2 = std::move(selfAssign2);

    sptr<IRemoteObject> nullRemote = nullptr;
    fw.SetParam(fdp->ConsumeRandomLengthString(MAX_LENGTH), nullRemote);
    fw.GetRemoteObject(fdp->ConsumeRandomLengthString(MAX_LENGTH));

    FormWant emptyFw;
    FormWant copiedEmpty(emptyFw);

    Want emptyWant;
    FormWant fromEmptyWant(emptyWant);

    emptyFw.GetWant();
    emptyFw.GetFilteredWant();

    Want emptyTarget;
    emptyFw.ExtractHostParamsToWant(emptyTarget);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();
    switch (testType % 6) {
        case 0:
            TestConstructors(fdp);
            break;
        case 1:
            TestSetParamVariants(fdp);
            break;
        case 2:
            TestGetParamVariants(fdp);
            break;
        case 3:
            TestGetWant(fdp);
            break;
        case 4:
            TestFilterAndMerge(fdp);
            break;
        case 5:
            TestEdgeCases(fdp);
            break;
        default:
            break;
    }

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
