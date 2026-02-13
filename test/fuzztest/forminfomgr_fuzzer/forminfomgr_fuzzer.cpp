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

#include "forminfomgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "data_center/form_info/form_info_mgr.h"
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
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();
    std::string bundleName(data, size);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formInfoMgr.UpdateStaticFormInfos(bundleName, userId);
    formInfoMgr.Remove(bundleName, userId);
    FormInfo formInfo;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(formInfo);
    formInfoMgr.GetAllFormsInfo(formInfos);
    formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos);
    std::string moduleName(data, size);
    formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos);
    BundleInfo bundleInfo;
    formInfoMgr.CheckDynamicFormInfo(formInfo, bundleInfo);
    formInfoMgr.AddDynamicFormInfo(formInfo, userId);
    std::string formName(data, size);
    formInfoMgr.RemoveDynamicFormInfo(bundleName, moduleName, formName, userId);
    formInfoMgr.RemoveAllDynamicFormsInfo(bundleName, userId);
    formInfoMgr.GetOrCreateBundleFromInfo(bundleName);
    formInfoMgr.IsCaller(bundleName);
    formInfoMgr.CheckBundlePermission();
    formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos);
    FormInfoHelper formInfoHelper;
    formInfoHelper.LoadAbilityFormConfigInfo(bundleInfo, formInfos);
    formInfoHelper.GetResourceManager(bundleInfo);
    std::string formInfoStoragesJson(data, size);
    BundleFormInfo bundleFormInfo(bundleName);
    bundleFormInfo.InitFromJson(formInfoStoragesJson);
    bundleFormInfo.Remove(userId);
    bundleFormInfo.AddDynamicFormInfo(formInfo, userId);
    bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId);
    bundleFormInfo.RemoveAllDynamicFormsInfo(userId);
    bundleFormInfo.Empty();
    bundleFormInfo.GetAllFormsInfo(formInfos, userId);
    FormInfoFilter filter;
    bundleFormInfo.GetFormsInfoByFilter(filter, formInfos, userId);
    bundleFormInfo.UpdateFormInfoStorageLocked();
    return formInfoMgr.ReloadFormInfos(userId);
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

