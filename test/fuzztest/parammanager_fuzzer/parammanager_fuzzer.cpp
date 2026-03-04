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

#include "parammanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "feature/param_update/param_manager.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    ParamManager &paramManager = ParamManager::GetInstance();

    // Test public method InitParam
    paramManager.InitParam();

    // Test public method GetParamStr
    const std::string &paramStr = paramManager.GetParamStr();

    // Test public method GetParamVersion
    const std::string &paramVersion = paramManager.GetParamVersion();

    // Test private method ReloadParam
    std::string versionStr = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string path = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    paramManager.ReloadParam(versionStr, path);

    // Test private method LoadVersion
    std::string loadedVersion = paramManager.LoadVersion();

    // Test private method LoadParamStr
    std::string loadedParam = paramManager.LoadParamStr();

    // Test private method SaveVersionStr
    std::string versionStrToSave = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    paramManager.SaveVersionStr(versionStrToSave);

    // Test private method SaveParamStr
    std::string paramStrToSave = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    paramManager.SaveParamStr(paramStrToSave);

    // Test private method VersionStrToNumber
    std::string versionStrToConvert = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    long long versionNum = 0;
    bool convertResult = paramManager.VersionStrToNumber(versionStrToConvert, versionNum);

    // Test private member g_paramStr
    std::string gParamStr = paramManager.g_paramStr;

    // Test private member g_currentVersion
    std::string gCurrentVersion = paramManager.g_currentVersion;

    return !paramStr.empty() || !paramVersion.empty() || convertResult;
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
