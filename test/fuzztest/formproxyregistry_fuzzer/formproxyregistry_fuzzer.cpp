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
constexpr int32_t MAX_REG_ITERATIONS = 5;
constexpr int32_t NUM_TEST_CASES = 8;

void TestDeathRecipient(FuzzedDataProvider *fdp)
{
    int32_t uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    bool callbackCalled = false;
    FormProxyDeathRecipient::CleanupCallback callback = [&callbackCalled](int32_t diedUid) {
        callbackCalled = true;
    };
    FormProxyDeathRecipient deathRecipient(uid, callback);

    wptr<IRemoteObject> remoteObj = nullptr;
    deathRecipient.OnRemoteDied(remoteObj);
}

void TestRegisterWithNullProxy(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    int32_t callingUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> nullProxy = nullptr;
    (void)registry.Register(callingUid, nullProxy);

    (void)registry.Register(callingUid, nullProxy);

    int32_t numRegs = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REG_ITERATIONS);
    for (int32_t i = 0; i < numRegs; i++) {
        int32_t uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        registry.Register(uid, nullProxy);
    }

    registry.Clear();
}

void TestRegisterOverwriteExisting(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    int32_t callingUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> nullProxy = nullptr;
    registry.proxies_[callingUid] = nullProxy;
    (void)registry.Register(callingUid, nullProxy);

    registry.Clear();
}

void TestUnregister(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    int32_t nonExistUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    (void)registry.Unregister(nonExistUid);

    int32_t uid1 = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    int32_t uid2 = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> nullProxy = nullptr;
    registry.proxies_[uid1] = nullProxy;
    registry.proxies_[uid2] = nullProxy;

    (void)registry.Unregister(uid1);
    (void)registry.Unregister(uid1);
    (void)registry.Unregister(uid2);

    registry.Clear();
}

void TestGet(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    int32_t nonExistKey = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> outProxy = nullptr;
    (void)registry.Get(nonExistKey, outProxy);

    int32_t existKey = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> nullProxy = nullptr;
    registry.proxies_[existKey] = nullProxy;

    sptr<IRemoteObject> foundProxy = nullptr;
    (void)registry.Get(existKey, foundProxy);

    int32_t anotherKey = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> anotherProxy = nullptr;
    (void)registry.Get(anotherKey, anotherProxy);

    registry.Clear();
}

void TestGetAll(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    std::vector<sptr<IRemoteObject>> proxies;
    (void)registry.GetAll(proxies);

    int32_t numEntries = fdp->ConsumeIntegralInRange(1, MAX_REG_ITERATIONS);
    sptr<IRemoteObject> nullProxy = nullptr;
    for (int32_t i = 0; i < numEntries; i++) {
        int32_t uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        registry.proxies_[uid] = nullProxy;
    }

    std::vector<sptr<IRemoteObject>> populatedProxies;
    (void)registry.GetAll(populatedProxies);

    registry.Clear();
}

void TestSize(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    (void)registry.Size();

    int32_t numEntries = fdp->ConsumeIntegralInRange(1, MAX_REG_ITERATIONS);
    sptr<IRemoteObject> nullProxy = nullptr;
    for (int32_t i = 0; i < numEntries; i++) {
        int32_t uid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        registry.proxies_[uid] = nullProxy;
    }
    (void)registry.Size();

    registry.Clear();
    (void)registry.Size();
}

void TestExistingCoverage(FuzzedDataProvider *fdp)
{
    std::string tag = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormProxyRegistry registry(tag);

    int32_t numRegs = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_REG_ITERATIONS);
    for (int32_t i = 0; i < numRegs; i++) {
        int32_t callingUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
        sptr<IRemoteObject> proxy = nullptr;
        registry.Register(callingUid, proxy);
    }

    std::vector<std::pair<int32_t, sptr<IRemoteObject>>> entries;
    registry.GetAllWithKeys(entries);

    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    std::vector<sptr<IRemoteObject>> proxies;
    registry.GetByUserId(userId, proxies);

    registry.Clear();

    int32_t addUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> addProxy = nullptr;
    registry.AddDeathRecipient(addUid, addProxy);

    int32_t removeUid = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    sptr<IRemoteObject> removeProxy = nullptr;
    registry.RemoveDeathRecipient(removeUid, removeProxy);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();

    switch (testType % NUM_TEST_CASES) {
        case 0:
            TestDeathRecipient(fdp);
            break;
        case 1:
            TestRegisterWithNullProxy(fdp);
            break;
        case 2:
            TestRegisterOverwriteExisting(fdp);
            break;
        case 3:
            TestUnregister(fdp);
            break;
        case 4:
            TestGet(fdp);
            break;
        case 5:
            TestGetAll(fdp);
            break;
        case 6:
            TestSize(fdp);
            break;
        case 7:
            TestExistingCoverage(fdp);
            break;
        default:
            TestDeathRecipient(fdp);
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
