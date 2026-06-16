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

#include "formabilityconnectionreporter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/connection/form_ability_connection_reporter.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormAbilityConnectionReporter formAbilityConnectionReporter;
    
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string emptyBundleName = "";
    
    bool isConnected = fdp->ConsumeBool();
    
    formAbilityConnectionReporter.ReportFormAbilityConnection(bundleName);
    formAbilityConnectionReporter.ReportFormAbilityConnection(emptyBundleName);
    
    formAbilityConnectionReporter.GetAppMgr();
    
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t numInfos = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < numInfos; i++) {
        AppExecFwk::RunningProcessInfo info;
        info.pid_ = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        infos.emplace_back(info);
    }
    
    formAbilityConnectionReporter.AddFormAbilityConnectProcessInfo(bundleName, infos);
    formAbilityConnectionReporter.AddFormAbilityConnectProcessInfo(emptyBundleName, infos);
    
    formAbilityConnectionReporter.ReportConnectionInfosToRss(bundleName, isConnected);
    formAbilityConnectionReporter.ReportConnectionInfosToRss(emptyBundleName, !isConnected);
    
    formAbilityConnectionReporter.ReportFormAbilityDisconnection(bundleName);
    formAbilityConnectionReporter.ReportFormAbilityDisconnection(emptyBundleName);
    
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
