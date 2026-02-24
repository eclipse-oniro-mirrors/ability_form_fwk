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

#include "forminfomgrTwo_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "data_center/form_info/form_info_mgr.h"
#include "form_info_filter.h"
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
    FormInfoMgr &formInfoMgr = FormInfoMgr::GetInstance();
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));

    // Test GetAllTemplateFormsInfo
    std::vector<FormInfo> formInfos;
    formInfoMgr.GetAllTemplateFormsInfo(formInfos, userId);
    formInfoMgr.GetAllTemplateFormsInfo(formInfos);

    // Test GetTemplateFormsInfoByBundle
    formInfoMgr.GetTemplateFormsInfoByBundle(bundleName, formInfos, userId);
    formInfoMgr.GetTemplateFormsInfoByBundle(bundleName, formInfos);

    // Test GetTemplateFormsInfoByModule
    formInfoMgr.GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos, userId);
    formInfoMgr.GetTemplateFormsInfoByModule(bundleName, moduleName, formInfos);

    // Test GetFormsInfoByFilter
    FormInfoFilter filter;
    formInfoMgr.GetFormsInfoByFilter(filter, formInfos, userId);
    formInfoMgr.GetFormsInfoByFilter(filter, formInfos);

    // Test GetFormsInfoByRecord
    FormRecord formRecord;
    formRecord.bundleName = bundleName;
    formRecord.moduleName = moduleName;
    FormInfo formInfo;
    formInfoMgr.GetFormsInfoByRecord(formRecord, formInfo);

    // Test GetFormsInfoByModuleWithoutCheck
    formInfoMgr.GetFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
    formInfoMgr.GetFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos);

    // Test GetTemplateFormsInfoByModuleWithoutCheck
    formInfoMgr.GetTemplateFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
    formInfoMgr.GetTemplateFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos);

    // Test PublishFmsReadyEvent
    formInfoMgr.PublishFmsReadyEvent();

    // Test HasReloadedFormInfos
    formInfoMgr.HasReloadedFormInfos();

    // Test GetAppFormVisibleNotifyByBundleName
    bool appFormVisibleNotify = false;
    formInfoMgr.GetAppFormVisibleNotifyByBundleName(bundleName, userId, appFormVisibleNotify);

    // Test IsMultiAppForm
    FormInfo testFormInfo;
    testFormInfo.bundleName = bundleName;
    formInfoMgr.IsMultiAppForm(testFormInfo);

    // Test IsTemplateFormImperativeFwkValid
    formInfoMgr.IsTemplateFormImperativeFwkValid(testFormInfo);

    // Test IsDeleteCacheInUpgradeScene
    formInfoMgr.IsDeleteCacheInUpgradeScene(testFormInfo);

    // Test private methods with different inputs
    std::map<std::string, std::uint32_t> bundleVersionMap;
    formInfoMgr.GetBundleVersionMap(bundleVersionMap, userId);
    formInfoMgr.UpdateBundleFormInfos(bundleVersionMap, userId);

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
