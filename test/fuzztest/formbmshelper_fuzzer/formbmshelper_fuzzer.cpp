/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formbmshelper_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "bms_mgr/form_bms_helper.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI1(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI2(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI3(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI4(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI5(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI6(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI7(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI8(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI9(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI10(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI11(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI12(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI13(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI14(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI15(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI16(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI17(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI18(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}

bool DoSomethingInterestingWithMyAPI19(const char* data, size_t size)
{
    FormBmsHelper formBmsHelper;
    sptr<IBundleMgr> bundleManager = nullptr;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    formBmsHelper.GenerateModuleKey(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    BundleInfo bundleInfo;
    formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo);
    formBmsHelper.GetUidByBundleName(bundleName, userId);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = reinterpret_cast<char *>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

