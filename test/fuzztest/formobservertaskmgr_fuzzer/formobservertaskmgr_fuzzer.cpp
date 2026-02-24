/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "formobservertaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_observer/form_observer_task_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
void DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return;
    }

    // Test with random bundle name
    std::string bundleName = fdp->ConsumeRandomLengthString();
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;

    // Test PostAddTaskToHost with fuzzed data
    runningFormInfo.formId = fdp->ConsumeIntegral<int64_t>();
    runningFormInfo.dimension = fdp->ConsumeIntegral<int32_t>();
    runningFormInfo.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegral<int32_t>());
    runningFormInfo.formVisiblity = static_cast<FormVisibilityType>(fdp->ConsumeIntegral<int32_t>());
    runningFormInfo.formUsageState = static_cast<FormUsageState>(fdp->ConsumeIntegral<int32_t>());
    runningFormInfo.lowMemoryRecycleStatus = static_cast<LowMemoryRecycleStatus>(fdp->ConsumeIntegral<int32_t>());
    runningFormInfo.formBundleType = static_cast<BundleType>(fdp->ConsumeIntegral<int32_t>());
    runningFormInfo.appIndex = fdp->ConsumeIntegral<int32_t>();
    runningFormInfo.userId = fdp->ConsumeIntegral<int32_t>();
    FormObserverTaskMgr::GetInstance().PostAddTaskToHost(bundleName, remoteObject, runningFormInfo);

    // Test PostRemoveTaskToHost with fuzzed data
    FormObserverTaskMgr::GetInstance().PostRemoveTaskToHost(bundleName, remoteObject, runningFormInfo);

    // Test PostFormClickEventToHost with fuzzed data
    std::string formEventType = fdp->ConsumeRandomLengthString();
    FormObserverTaskMgr::GetInstance().PostFormClickEventToHost(bundleName, formEventType, remoteObject,
        runningFormInfo);

    // Test PostBatchRefreshForms with fuzzed refresh type
    int32_t formRefreshType = fdp->ConsumeIntegral<int32_t>();
    FormObserverTaskMgr::GetInstance().PostBatchRefreshForms(formRefreshType);

    // Test PostBatchConfigurationUpdateForms with fuzzed configuration
    AppExecFwk::Configuration configuration;
    FormObserverTaskMgr::GetInstance().PostBatchConfigurationUpdateForms(configuration);

    // Test direct private method calls with fuzzed data
    FormObserverTaskMgr::GetInstance().FormAdd(bundleName, remoteObject, runningFormInfo);
    FormObserverTaskMgr::GetInstance().FormRemove(bundleName, remoteObject, runningFormInfo);
    FormObserverTaskMgr::GetInstance().FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Use FuzzedDataProvider for more comprehensive testing
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);

    return 0;
}

