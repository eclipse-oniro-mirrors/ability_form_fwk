/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You can obtain a copy of the License at
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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define private public
#define protected public
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
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

    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();

    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);

    // Existing methods
    formInfoMgr.UpdateStaticFormInfos(bundleName, userId);
    formInfoMgr.Remove(bundleName, userId);

    std::vector<FormInfo> formInfos;
    formInfoMgr.GetAllFormsInfo(formInfos);
    formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos);
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos);

    FormInfo formInfo = GenerateFuzzedFormInfo(fdp);
    BundleInfo bundleInfo;
    formInfoMgr.CheckDynamicFormInfo(formInfo, bundleInfo);
    formInfoMgr.AddDynamicFormInfo(formInfo, userId);
    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfoMgr.RemoveDynamicFormInfo(bundleName, moduleName, formName, userId);
    formInfoMgr.RemoveAllDynamicFormsInfo(bundleName, userId);
    formInfoMgr.GetOrCreateBundleFromInfo(bundleName);
    formInfoMgr.IsCaller(bundleName);
    formInfoMgr.CheckBundlePermission();

    // NEW method: AddBundleFormInfos
    std::map<std::string, std::uint32_t> bundleVersionMap;
    int32_t mapSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < mapSize; i++) {
        std::string key = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        uint32_t value = fdp->ConsumeIntegral<uint32_t>();
        bundleVersionMap[key] = value;
    }
    formInfoMgr.AddBundleFormInfos(bundleVersionMap, userId);

    // NEW method: UpdateFormShowConfigs
    std::vector<FormCustomConfig> configs;
    int32_t configSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < configSize; i++) {
        configs.push_back(GenerateFuzzedFormCustomConfig(fdp));
    }
    formInfoMgr.UpdateFormShowConfigs(configs);

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
