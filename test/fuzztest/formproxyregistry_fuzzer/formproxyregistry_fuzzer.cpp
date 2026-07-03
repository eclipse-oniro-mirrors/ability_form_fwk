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

#include "formproxyregistry_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/util/form_proxy_registry.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // FormProxyDeathRecipient::FormProxyDeathRecipient
    int32_t uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    bool callbackCalled = false;
    FormProxyDeathRecipient::CleanupCallback callback = [&callbackCalled](int32_t diedUid) {
        callbackCalled = true;
    };
    FormProxyDeathRecipient deathRecipient(uid, callback);

    // FormProxyDeathRecipient::OnRemoteDied
    wptr<IRemoteObject> remoteObj = nullptr;
    deathRecipient.OnRemoteDied(remoteObj);

    // FormProxyRegistry constructor
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    // Register some proxies first (needed for GetAllWithKeys/GetByUserId/Clear to have data)
    int32_t numRegs = fdp->ConsumeIntegralInRange(0, 5);
    for (int32_t i = 0; i < numRegs; i++) {
        int32_t callingUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        sptr<IRemoteObject> proxy = nullptr;
        registry.Register(callingUid, proxy);
    }

    // GetAllWithKeys
    std::vector<std::pair<int32_t, sptr<IRemoteObject>>> entries;
    registry.GetAllWithKeys(entries);

    // GetByUserId
    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    std::vector<sptr<IRemoteObject>> proxies;
    registry.GetByUserId(userId, proxies);

    // Clear
    registry.Clear();

    // AddDeathRecipient (private, accessible via #define private public)
    int32_t addUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> addProxy = nullptr;
    registry.AddDeathRecipient(addUid, addProxy);

    // RemoveDeathRecipient (private)
    int32_t removeUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> removeProxy = nullptr;
    registry.RemoveDeathRecipient(removeUid, removeProxy);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
