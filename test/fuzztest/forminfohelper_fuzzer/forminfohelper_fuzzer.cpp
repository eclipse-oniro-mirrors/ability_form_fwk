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

#include "forminfohelper_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
#undef private
#undef protected
#include "securec.h"
#include "ffrt.h"

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_STR_LEN = 256;

static void TestFormInfoLoadAPIs(FuzzedDataProvider &fdp)
{
    // Test LoadStageFormConfigInfo
    BundleInfo bundleInfo;
    bundleInfo.appId = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    bundleInfo.versionCode = fdp.ConsumeIntegral<int32_t>();

    std::vector<FormInfo> formInfos;
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    FormInfoHelper::LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
    FormInfoHelper::LoadStageFormConfigInfo(bundleInfo, formInfos);

    // Test GetResourceManager
    auto resourceManager = FormInfoHelper::GetResourceManager(bundleInfo);

    // Test GetFormInfoDescription / GetFormInfoDisplayName
    FormInfo formInfo;
    formInfo.name = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    formInfo.bundleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    formInfo.moduleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    formInfo.descriptionId = fdp.ConsumeIntegral<int32_t>();
    FormInfoHelper::GetFormInfoDescription(resourceManager, formInfo);
    formInfo.displayName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    FormInfoHelper::GetFormInfoDisplayName(resourceManager, formInfo);

    // Test LoadSharedModuleInfo
    HapModuleInfo sharedModuleInfo;
    FormInfoHelper::LoadSharedModuleInfo(bundleInfo, sharedModuleInfo);

    // Test LoadFormInfos
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.bundleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    extensionInfo.moduleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    extensionInfo.name = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    extensionInfo.description = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    std::string profileInfo = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    ExtraFormInfo extraFormInfo;
    extraFormInfo.isDistributedForm = fdp.ConsumeBool();
    extraFormInfo.moduleName = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    extraFormInfo.isTemplateForm = fdp.ConsumeBool();
    FormInfoHelper::LoadFormInfos(formInfos, bundleInfo, extensionInfo, profileInfo, extraFormInfo);

    // Test PrintLoadStageFormConfigInfo / SetDistributedBundleStatus
    bool hasDistributedForm = fdp.ConsumeBool();
    FormInfoHelper::PrintLoadStageFormConfigInfo(formInfo, hasDistributedForm);
    FormInfoHelper::SetDistributedBundleStatus(userId, fdp.ConsumeRandomLengthString(MAX_STR_LEN),
        fdp.ConsumeRandomLengthString(MAX_STR_LEN), fdp.ConsumeRandomLengthString(MAX_STR_LEN),
        hasDistributedForm);
}

static void TestFormInfoUpdateAPIs(FuzzedDataProvider &fdp)
{
    BundleInfo bundleInfo;
    bundleInfo.name = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    std::vector<FormInfo> formInfos;
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    FormInfoHelper::UpdateFormInfoByAppServicesCapability(bundleInfo, userId, formInfos);
    FormInfoHelper::UpdateFormInfoTransparencyEnabled(bundleInfo, formInfos, fdp.ConsumeBool());
    FormInfoHelper::UpdateFormInfoFormStandby(bundleInfo, formInfos, fdp.ConsumeBool());

    // Test CheckAppServicesCapabilities and per-bundle ResourceManager reuse
    bool isTransparencyEnabled = false;
    bool isStandbyEnabled = false;
    FormInfoHelper::CheckAppServicesCapabilities(userId, bundleInfo.name,
        fdp.ConsumeRandomLengthString(MAX_STR_LEN), fdp.ConsumeRandomLengthString(MAX_STR_LEN),
        isTransparencyEnabled, isStandbyEnabled);

    ExtensionAbilityInfo extensionInfo;
    std::string profileInfo = fdp.ConsumeRandomLengthString(MAX_STR_LEN);
    ExtraFormInfo extraFormInfo;

    std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> resMgrCache;
    auto resMgr = FormInfoHelper::GetResMgr(resMgrCache, extensionInfo);
    std::vector<std::string> profilesFromMgr;
    FormInfoHelper::GetProfilesByResMgr(resMgr, extensionInfo,
        fdp.ConsumeRandomLengthString(MAX_STR_LEN), profilesFromMgr);

    // Test LoadProfileFormInfos
    std::vector<std::string> profileInfos;
    profileInfos.push_back(profileInfo);
    profileInfos.push_back(fdp.ConsumeRandomLengthString(MAX_STR_LEN));
    FormInfoHelper::LoadProfileFormInfos(formInfos, bundleInfo, extensionInfo, profileInfos, extraFormInfo);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);
    TestFormInfoLoadAPIs(fdp);
    TestFormInfoUpdateAPIs(fdp);
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < 1) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
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
