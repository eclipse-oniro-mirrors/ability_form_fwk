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

#include "formobserveradapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_observer_adapter.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_EVENT_TYPE_COUNT = 5;

std::vector<std::string> GenerateFormEventTypes()
{
    return { "call", "message", "router", "formAdd", "formRemove" };
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormObserverAdapter::GetInstance();

    // Fuzz RegisterFormAddObserverByBundle
    std::string addBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IRemoteObject> addCallerToken = nullptr;
    adapter.RegisterFormAddObserverByBundle(addBundleName, addCallerToken);

    // Fuzz RegisterFormRemoveObserverByBundle
    std::string removeBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IRemoteObject> removeCallerToken = nullptr;
    adapter.RegisterFormRemoveObserverByBundle(removeBundleName, removeCallerToken);

    // Fuzz RegisterAddObserver
    std::string addObserverBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IRemoteObject> addObserverCallerToken = nullptr;
    adapter.RegisterAddObserver(addObserverBundleName, addObserverCallerToken);

    // Fuzz RegisterRemoveObserver
    std::string removeObserverBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IRemoteObject> removeObserverCallerToken = nullptr;
    adapter.RegisterRemoveObserver(removeObserverBundleName, removeObserverCallerToken);

    // Fuzz CleanResource
    wptr<IRemoteObject> remoteObj = nullptr;
    adapter.CleanResource(remoteObj);

    // Fuzz RegisterClickEventObserver with nullptr observer (tests error path)
    std::string clickBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<std::string> eventTypes = GenerateFormEventTypes();
    int32_t eventTypeIndex = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_EVENT_TYPE_COUNT - 1);
    std::string formEventType = eventTypes[eventTypeIndex];
    sptr<IRemoteObject> clickObserver = nullptr;
    adapter.RegisterClickEventObserver(clickBundleName, formEventType, clickObserver);

    // Fuzz RegisterClickEventObserver with valid event type but nullptr observer
    std::string clickBundleName2 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t eventTypeIndex2 = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_EVENT_TYPE_COUNT - 1);
    std::string formEventType2 = eventTypes[eventTypeIndex2];
    adapter.RegisterClickEventObserver(clickBundleName2, formEventType2, clickObserver);

    // Fuzz UnregisterClickEventObserver with nullptr observer (tests error path)
    std::string unregisterBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t unregisterEventTypeIndex = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_EVENT_TYPE_COUNT - 1);
    std::string unregisterEventType = eventTypes[unregisterEventTypeIndex];
    sptr<IRemoteObject> unregisterObserver = nullptr;
    adapter.UnregisterClickEventObserver(unregisterBundleName, unregisterEventType, unregisterObserver);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
