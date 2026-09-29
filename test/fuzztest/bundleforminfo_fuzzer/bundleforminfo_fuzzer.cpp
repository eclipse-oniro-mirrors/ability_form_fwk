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

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/bundle_form_info.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_info_helper.h"
#include "ffrt.h"
#undef private
#undef protected

extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
}

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t MAX_LOOP_COUNT = 10;
constexpr int32_t TEST_TYPE_BASIC = 0;
constexpr int32_t TEST_TYPE_UPDATE_CONFIGS = 1;
constexpr int32_t TEST_TYPE_FORM_INFO_MGR = 2;
constexpr int32_t NUM_TEST_SCENARIOS = 3;

// nlohmann::json::dump() with default strict error_handler aborts on invalid UTF-8.
// Strip non-ASCII to guarantee valid UTF-8 for json serialization.
static std::string SanitizeUtf8(const std::string &input)
{
    std::string out;
    for (char c : input) {
        out += (static_cast<unsigned char>(c) <= 0x7F) ? c : '_';
    }
    return out;
}

static std::string ConsumeSanitizedString(FuzzedDataProvider *fdp)
{
    return SanitizeUtf8(fdp->ConsumeRandomLengthString(MAX_LENGTH));
}

FormInfo GenerateFuzzedFormInfo(FuzzedDataProvider *fdp)
{
    FormInfo formInfo;
    if (fdp == nullptr) {
        return formInfo;
    }
    formInfo.name = ConsumeSanitizedString(fdp);
    formInfo.bundleName = ConsumeSanitizedString(fdp);
    formInfo.moduleName = ConsumeSanitizedString(fdp);
    formInfo.abilityName = ConsumeSanitizedString(fdp);
    formInfo.versionCode = fdp->ConsumeIntegral<uint32_t>();
    formInfo.isDynamic = fdp->ConsumeBool();
    return formInfo;
}

FormCustomConfig GenerateFuzzedFormCustomConfig(FuzzedDataProvider *fdp)
{
    FormCustomConfig config;
    if (fdp == nullptr) {
        return config;
    }
    config.bundleName = ConsumeSanitizedString(fdp);
    config.moduleName = ConsumeSanitizedString(fdp);
    config.abilityName = ConsumeSanitizedString(fdp);
    config.formName = ConsumeSanitizedString(fdp);
    config.relatedBundleName = ConsumeSanitizedString(fdp);
    config.isShowInFormCenter = fdp->ConsumeBool();
    config.isRepeatAdditionSupported = fdp->ConsumeBool();
    return config;
}

void TestBundleFormInfoBasic(FuzzedDataProvider *fdp)
{
    std::string bundleName = ConsumeSanitizedString(fdp);
    BundleFormInfo bundleFormInfo(bundleName);

    std::string jsonStr = ConsumeSanitizedString(fdp);
    bundleFormInfo.InitFromJson(jsonStr);

    bundleFormInfo.Empty();

    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);
    std::vector<FormInfo> formInfos;
    bundleFormInfo.GetAllFormsInfo(formInfos, userId);
    bundleFormInfo.GetAllTemplateFormsInfo(formInfos, userId);
    bundleFormInfo.GetVersionCode(userId);

    std::string moduleName = ConsumeSanitizedString(fdp);
    bundleFormInfo.GetFormsInfoByModule(moduleName, formInfos, userId);
    bundleFormInfo.GetTemplateFormsInfoByModule(moduleName, formInfos, userId);

    FormInfoFilter filter;
    filter.bundleName = bundleName;
    filter.moduleName = moduleName;
    bundleFormInfo.GetFormsInfoByFilter(filter, formInfos, userId);

    bundleFormInfo.UpdateStaticFormInfos(formInfos, userId);
    bundleFormInfo.Remove(userId);

    FormInfo formInfo = GenerateFuzzedFormInfo(fdp);
    bundleFormInfo.AddDynamicFormInfo(formInfo, userId);

    std::string formName = ConsumeSanitizedString(fdp);
    bundleFormInfo.RemoveDynamicFormInfo(moduleName, formName, userId);
    bundleFormInfo.RemoveAllDynamicFormsInfo(userId);
}

void TestBundleFormInfoUpdateConfigs(FuzzedDataProvider *fdp)
{
    std::string bundleName = ConsumeSanitizedString(fdp);
    BundleFormInfo bundleFormInfo(bundleName);

    std::vector<FormCustomConfig> configs;
    int32_t configSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < configSize; i++) {
        configs.push_back(GenerateFuzzedFormCustomConfig(fdp));
    }
    bundleFormInfo.UpdateFormShowConfigs(configs);
}

void TestFormInfoMgrWithBundleFormInfo(FuzzedDataProvider *fdp)
{
    FormInfoMgr formInfoMgr;
    formInfoMgr.Start();

    std::string bundleName = ConsumeSanitizedString(fdp);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);

    formInfoMgr.UpdateStaticFormInfos(bundleName, userId);
    formInfoMgr.Remove(bundleName, userId);

    std::vector<FormInfo> formInfos;
    formInfoMgr.GetAllFormsInfo(formInfos);
    formInfoMgr.GetFormsInfoByBundle(bundleName, formInfos);

    std::string moduleName = ConsumeSanitizedString(fdp);
    formInfoMgr.GetFormsInfoByModule(bundleName, moduleName, formInfos);

    FormInfo formInfo = GenerateFuzzedFormInfo(fdp);
    formInfoMgr.AddDynamicFormInfo(formInfo, userId);

    std::string formName = ConsumeSanitizedString(fdp);
    formInfoMgr.RemoveDynamicFormInfo(bundleName, moduleName, formName, userId);
    formInfoMgr.RemoveAllDynamicFormsInfo(bundleName, userId);

    std::vector<FormCustomConfig> configs;
    int32_t configSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_LOOP_COUNT);
    for (int32_t i = 0; i < configSize; i++) {
        configs.push_back(GenerateFuzzedFormCustomConfig(fdp));
    }
    formInfoMgr.UpdateFormShowConfigs(configs);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();
    switch (testType % NUM_TEST_SCENARIOS) {
        case TEST_TYPE_BASIC:
            TestBundleFormInfoBasic(fdp);
            break;
        case TEST_TYPE_UPDATE_CONFIGS:
            TestBundleFormInfoUpdateConfigs(fdp);
            break;
        case TEST_TYPE_FORM_INFO_MGR:
            TestFormInfoMgrWithBundleFormInfo(fdp);
            break;
        default:
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
