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

#define private public
#define protected public
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
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
    // Test LoadStageFormConfigInfo
    BundleInfo bundleInfo;
    bundleInfo.appId = std::string(data, size);
    bundleInfo.versionCode = static_cast<int32_t>(GetU32Data(data));

    std::vector<FormInfo> formInfos;
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    FormInfoHelper::LoadStageFormConfigInfo(bundleInfo, formInfos, userId);
    FormInfoHelper::LoadStageFormConfigInfo(bundleInfo, formInfos);

    // Test GetResourceManager
    auto resourceManager = FormInfoHelper::GetResourceManager(bundleInfo);

    // Test GetFormInfoDescription
    FormInfo formInfo;
    formInfo.name = std::string(data, size);
    formInfo.bundleName = std::string(data, size);
    formInfo.moduleName = std::string(data, size);
    formInfo.descriptionId = static_cast<int32_t>(GetU32Data(data));
    FormInfoHelper::GetFormInfoDescription(resourceManager, formInfo);

    // Test GetFormInfoDisplayName
    formInfo.displayName = std::string(data, size);
    FormInfoHelper::GetFormInfoDisplayName(resourceManager, formInfo);

    // Test LoadSharedModuleInfo
    HapModuleInfo sharedModuleInfo;
    FormInfoHelper::LoadSharedModuleInfo(bundleInfo, sharedModuleInfo);

    // Test LoadFormInfos
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.bundleName = std::string(data, size);
    extensionInfo.moduleName = std::string(data, size);
    extensionInfo.name = std::string(data, size);
    extensionInfo.description = std::string(data, size);

    std::string profileInfo(data, size);
    ExtraFormInfo extraFormInfo;
    extraFormInfo.isDistributedForm = (GetU32Data(data) % 2 == 0);
    extraFormInfo.moduleName = std::string(data, size);
    extraFormInfo.isTemplateForm = (GetU32Data(data) % 3 == 0);

    FormInfoHelper::LoadFormInfos(formInfos, bundleInfo, extensionInfo, profileInfo, extraFormInfo);

    // Test PrintLoadStageFormConfigInfo
    bool hasDistributedForm = (GetU32Data(data) % 2 == 0);
    FormInfoHelper::PrintLoadStageFormConfigInfo(formInfo, hasDistributedForm);

    // Test SetDistributedBundleStatus
    std::string entryModule(data, size);
    std::string uiModule(data, size);
    std::string bundleInfoName(data, size);
    FormInfoHelper::SetDistributedBundleStatus(userId, entryModule, uiModule, bundleInfoName, hasDistributedForm);

    // Test SendLoadStageFormConfigEvent
    FormInfoHelper::SendLoadStageFormConfigEvent(formInfo);

    // Test GetBundleTransparencyEnabled
    std::string bundleName(data, size);
    FormInfoHelper::GetBundleTransparencyEnabled(bundleName, userId);

    // Test UpdateBundleTransparencyEnabled
    FormInfoHelper::UpdateBundleTransparencyEnabled(bundleName, userId, formInfos);

    // Test LoadProfileFormInfos
    std::vector<std::string> profileInfos;
    profileInfos.push_back(profileInfo);
    profileInfos.push_back(std::string(data, size));
    FormInfoHelper::LoadProfileFormInfos(formInfos, bundleInfo, extensionInfo, profileInfos, extraFormInfo);

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
