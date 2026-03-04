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

#include "bundleforminfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/bundle_form_info.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = -10000;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    BundleFormInfo bundleFormInfo(bundleName);

    std::string formInfoStoragesJson = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.InitFromJson(formInfoStoragesJson);

    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    bundleFormInfo.UpdateStaticFormInfos(userId);

    bundleFormInfo.Remove(userId);

    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId);

    bundleFormInfo.RemoveAllDynamicFormsInfo(userId);

    bundleFormInfo.Empty();

    std::vector<FormInfo> formInfos;
    bundleFormInfo.GetAllFormsInfo(formInfos, userId);

    bundleFormInfo.GetAllTemplateFormsInfo(formInfos, userId);

    bundleFormInfo.GetVersionCode(userId);

    bundleFormInfo.GetFormsInfoByModule(moduleName, formInfos, userId);

    bundleFormInfo.GetTemplateFormsInfoByModule(moduleName, formInfos, userId);

    FormInfoFilter filter;
    filter.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.GetFormsInfoByFilter(filter, formInfos, userId);

    bundleFormInfo.UpdateFormInfoStorageLocked();

    std::vector<FormInfo> inFormInfos;
    std::vector<FormInfo> outFormInfos;
    std::vector<FormDBInfo> formDBInfos;
    int32_t numInForms = fdp->ConsumeIntegralInRange(0, 10);
    int32_t numDBInfos = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numInForms; i++) {
        FormInfo info;
        info.name = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        inFormInfos.push_back(info);
    }
    for (int32_t i = 0; i < numDBInfos; i++) {
        FormDBInfo dbInfo;
        dbInfo.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        formDBInfos.push_back(dbInfo);
    }
    bundleFormInfo.HandleFormInfosMaxLimit(inFormInfos, outFormInfos, formDBInfos);

    std::set<std::string> formDBNames;
    int32_t numDBNames = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numDBNames; i++) {
        formDBNames.insert(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    }
    bundleFormInfo.GetAllUsedFormName(formDBInfos, inFormInfos, formDBNames);

    bundleFormInfo.ClearDistributedFormInfos(userId);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
