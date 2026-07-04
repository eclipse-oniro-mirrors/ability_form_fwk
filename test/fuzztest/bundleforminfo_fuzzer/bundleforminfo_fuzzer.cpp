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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define private public
#define protected public
#include "data_center/form_info/bundle_form_info.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;

FormInfo GenerateFuzzedFormInfo(FuzzedDataProvider *fdp)
{
    FormInfo formInfo;
    if (fdp == nullptr) {
        return formInfo;
    }
    formInfo.name = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    return formInfo;
}

FormCustomConfig GenerateFuzzedFormCustomConfig(FuzzedDataProvider *fdp)
{
    FormCustomConfig config;
    if (fdp == nullptr) {
        return config;
    }
    config.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    return config;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // Initialize FormInfoMgr to ensure necessary singletons and database are initialized
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();

    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    BundleFormInfo bundleFormInfo(bundleName);

    std::string formInfoStoragesJson = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.InitFromJson(formInfoStoragesJson);

    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);

    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);

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

    // NEW: UpdateStaticFormInfos
    std::vector<FormInfo> updateFormInfos;
    int32_t updateSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < updateSize; i++) {
        updateFormInfos.push_back(GenerateFuzzedFormInfo(fdp));
    }
    bundleFormInfo.UpdateStaticFormInfos(updateFormInfos, userId);

    // NEW: IsFormInfoMatched
    FormInfo matchFormInfo = GenerateFuzzedFormInfo(fdp);
    FormCustomConfig matchConfig;
    matchConfig.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    matchConfig.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    matchConfig.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    matchConfig.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.IsFormInfoMatched(matchFormInfo, matchConfig);

    // NEW: UpdateFormShowConfigInCustomizeDatas
    FormInfo showFormInfo = GenerateFuzzedFormInfo(fdp);
    bool isShow = fdp->ConsumeBool();
    bundleFormInfo.UpdateFormShowConfigInCustomizeDatas(showFormInfo, isShow);

    // NEW: ApplyConfigToStorages
    FormCustomConfig applyConfig;
    applyConfig.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    applyConfig.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    applyConfig.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    applyConfig.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bundleFormInfo.ApplyConfigToStorages(applyConfig);

    // NEW: UpdateFormShowConfigs
    std::vector<FormCustomConfig> showConfigs;
    int32_t showSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < showSize; i++) {
        showConfigs.push_back(GenerateFuzzedFormCustomConfig(fdp));
    }
    bundleFormInfo.UpdateFormShowConfigs(showConfigs);

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
