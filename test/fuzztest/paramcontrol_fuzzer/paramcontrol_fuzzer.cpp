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

#include "paramcontrol_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "feature/param_update/param_control.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_NUM = 15; // max

/**
 * @brief Generate fuzzed FormRecord with comprehensive field coverage
 */
FormRecord GenerateFuzzedFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord formRecord;
    if (fdp == nullptr) {
        return formRecord;
    }
    formRecord.formId = fdp->ConsumeIntegral<int64_t>();
    formRecord.bundleName = fdp->ConsumeRandomLengthString(MAX_NUM);
    formRecord.moduleName = fdp->ConsumeRandomLengthString(MAX_NUM);
    formRecord.abilityName = fdp->ConsumeRandomLengthString(MAX_NUM);
    formRecord.formName = fdp->ConsumeRandomLengthString(MAX_NUM);
    formRecord.specification = fdp->ConsumeIntegral<int32_t>();
    formRecord.isEnableUpdate = fdp->ConsumeBool();
    formRecord.updateDuration = fdp->ConsumeIntegral<int64_t>();
    formRecord.versionCode = fdp->ConsumeIntegral<uint32_t>();
    formRecord.lastVersionCode = fdp->ConsumeIntegral<uint32_t>();
    formRecord.versionName = fdp->ConsumeRandomLengthString(MAX_NUM);
    formRecord.formTempFlag = fdp->ConsumeBool();
    formRecord.userId = fdp->ConsumeIntegral<int32_t>();
    formRecord.providerUserId = fdp->ConsumeIntegral<int32_t>();
    formRecord.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegral<int32_t>());
    formRecord.formBundleType = static_cast<BundleType>(fdp->ConsumeIntegral<int32_t>());
    return formRecord;
}

/**
 * @brief Generate various JSON strings for testing DealDueParam
 */
std::string GenerateFuzzedJsonString(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return "";
    }
    uint8_t jsonType = fdp->ConsumeIntegral<uint8_t>() % 5;
    switch (jsonType) {
        case 0: // Empty string
            return "";
        case 1: // Valid JSON with formUpdateDurationCtrl
            return R"({"formUpdateDurationCtrl":[{"bundleName":"test.bundle", "moduleName":
                "testModule", "updateDuration":10}]})";
        case 2: // Valid JSON with formDisableCtrl
            return R"({"formDisableCtrl":[{"bundleName":"test.bundle", "moduleName":"testModule",
                "policy":"disable"}]})";
        case 3: // Valid JSON with both controls
            return R"({"formUpdateDurationCtrl":[{"bundleName":"test.bundle", "moduleName":
                "testModule", "updateDuration":10}], "formDisableCtrl":[{"bundleName":"test.bundle",
                "moduleName":"testModule", "policy":"disable"}]})";
        case 4: // Invalid JSON string
        default:
            return fdp->ConsumeRandomLengthString(MAX_NUM);
    }
}

/**
 * @brief Test ParamControl public APIs with comprehensive input
 */
void TestParamControlPublicAPIs(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return;
    }
    // Test DealDueParam with various JSON strings
    std::string jsonStr = GenerateFuzzedJsonString(fdp);
    ParamControl::GetInstance().DealDueParam(jsonStr);

    // Test with fuzzed FormRecord
    FormRecord formRecord = GenerateFuzzedFormRecord(fdp);
    ParamControl::GetInstance().GetDueUpdateDuration(formRecord);
    ParamControl::GetInstance().IsFormDisable(formRecord);
    ParamControl::GetInstance().IsFormRemove(formRecord);

    // Test with vector of FormRecords
    std::vector<FormRecord> formRecords;
    size_t vectorSize = fdp->ConsumeIntegralInRange<size_t>(0, 5);
    for (size_t i = 0; i < vectorSize; ++i) {
        formRecords.push_back(GenerateFuzzedFormRecord(fdp));
    }
    ParamControl::GetInstance().ReloadDueControlByAppUpgrade(formRecords);
    ParamControl::GetInstance().IsDueDisableCtrlEmpty();
}

/**
 * @brief Test ParamControl private methods via public access
 */
void TestParamControlPrivateMethods(FuzzedDataProvider *fdp)
{
    ParamControl &paramControl = ParamControl::GetInstance();

    // Test ParamTransfer
    paramControl.ParamTransfer();

    // Test ParseJsonToObj with various inputs
    std::string jsonStr = GenerateFuzzedJsonString(fdp);
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    if (!jsonObject.is_discarded() && jsonObject.is_object()) {
        paramControl.ParseJsonToObj(jsonObject);
    }

    // Test IsParamValid with fuzzed ParamCtrl
    ParamCtrl paramCtrl;
    paramCtrl.bundleName = fdp->ConsumeRandomLengthString(MAX_NUM);
    paramCtrl.moduleName = fdp->ConsumeRandomLengthString(MAX_NUM);
    paramCtrl.abilityName = fdp->ConsumeRandomLengthString(MAX_NUM);
    paramCtrl.formName = fdp->ConsumeRandomLengthString(MAX_NUM);
    paramCtrl.dimensions.push_back(fdp->ConsumeIntegral<int32_t>());
    paramCtrl.appVersionStart = fdp->ConsumeIntegral<uint32_t>();
    paramCtrl.appVersionEnd = fdp->ConsumeIntegral<uint32_t>();
    paramCtrl.updateDuration = fdp->ConsumeIntegral<int32_t>();
    paramCtrl.policy = fdp->ConsumeRandomLengthString(MAX_NUM);

    bool isDisableCtrl = fdp->ConsumeBool();
    paramControl.IsParamValid(paramCtrl, isDisableCtrl);

    // Test IsFormInfoMatch with fuzzed FormRecord and ParamCtrl
    FormRecord formRecord = GenerateFuzzedFormRecord(fdp);
    bool isNewVersion = fdp->ConsumeBool();
    paramControl.IsFormInfoMatch(formRecord, paramCtrl, isNewVersion);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // Test public APIs
    TestParamControlPublicAPIs(fdp);

    // Test private methods
    bool testPrivateMethods = fdp->ConsumeBool();
    if (testPrivateMethods) {
        TestParamControlPrivateMethods(fdp);
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
