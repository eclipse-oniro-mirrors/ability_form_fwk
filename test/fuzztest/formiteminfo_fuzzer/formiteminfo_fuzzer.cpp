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

#include "formiteminfo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_item_info.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormItemInfo formItemInfo;
    std::string dir(data, size);
    std::vector<std::string> dirs;
    dirs.emplace_back(dir);
    formItemInfo.SetHapSourceDirs(dirs);
    formItemInfo.GetHapSourceDirs(dirs);
    formItemInfo.IsTemporaryForm();
    std::string moduleName(data, size);
    formItemInfo.GetHapSourceByModuleName(moduleName);
    formItemInfo.IsValidItem();
    FormRecord record;
    formItemInfo.IsMatch(record);
    formItemInfo.IsSameFormConfig(record);
    formItemInfo.IsFormVisibleNotify();
    std::string left(data, size);
    std::string right(data, size);
    formItemInfo.IsEqual(left, right);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    formItemInfo.SetFormId(formId);
    std::string packageName(data, size);
    formItemInfo.SetPackageName(packageName);
    std::string providerBundleName(data, size);
    formItemInfo.SetProviderBundleName(providerBundleName);
    std::string hostBundleName(data, size);
    formItemInfo.SetHostBundleName(hostBundleName);
    formItemInfo.SetModuleName(moduleName);
    std::string abilityName(data, size);
    formItemInfo.SetAbilityName(abilityName);
    std::string formName(data, size);
    formItemInfo.SetFormName(formName);
    std::string jsComponentName(data, size);
    formItemInfo.SetJsComponentName(jsComponentName);
    std::string abilityModuleName(data, size);
    formItemInfo.SetAbilityModuleName(abilityModuleName);
    int specificationId = static_cast<int>(GetU32Data(data));
    formItemInfo.SetSpecificationId(specificationId);
    bool isEnableUpdateFlag = *data % ENABLE;
    formItemInfo.SetEnableUpdateFlag(isEnableUpdateFlag);
    int updateDuration = static_cast<int>(GetU32Data(data));
    formItemInfo.SetUpdateDuration(updateDuration);
    std::string scheduledUpdateTime(data, size);
    formItemInfo.SetScheduledUpdateTime(scheduledUpdateTime);
    std::string hapSourceDir(data, size);
    formItemInfo.AddHapSourceDirs(hapSourceDir);
    formItemInfo.GetFormId();
    formItemInfo.GetPackageName();
    formItemInfo.GetProviderBundleName();
    formItemInfo.GetHostBundleName();
    formItemInfo.GetModuleName();
    formItemInfo.GetAbilityName();
    formItemInfo.GetFormName();
    formItemInfo.GetJsComponentName();
    formItemInfo.GetAbilityModuleName();
    formItemInfo.GetSpecificationId();
    formItemInfo.GetUpdateDuration();
    formItemInfo.GetScheduledUpdateTime();
    bool temporaryFlag = *data % ENABLE;
    formItemInfo.SetTemporaryFlag(temporaryFlag);
    std::string moduleSourceDir(data, size);
    formItemInfo.AddModuleInfo(moduleName, moduleSourceDir);
    return formItemInfo.IsEnableUpdateFlag();
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

