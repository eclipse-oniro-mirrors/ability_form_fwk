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

// UTF-8 encoding byte boundaries per RFC 3629
static constexpr unsigned char UTF8_ASCII_MAX = 0x7F;
static constexpr unsigned char UTF8_TWO_BYTE_LEAD_MIN = 0xC2;
static constexpr unsigned char UTF8_TWO_BYTE_LEAD_MAX = 0xDF;
static constexpr unsigned char UTF8_THREE_BYTE_LEAD_MIN = 0xE0;
static constexpr unsigned char UTF8_THREE_BYTE_LEAD_MAX = 0xEF;
static constexpr unsigned char UTF8_FOUR_BYTE_LEAD_MIN = 0xF0;
static constexpr unsigned char UTF8_FOUR_BYTE_LEAD_MAX = 0xF4;
static constexpr unsigned char UTF8_CONTINUATION_MASK = 0xC0;
static constexpr unsigned char UTF8_CONTINUATION_VALUE = 0x80;
static constexpr int32_t UTF8_TWO_BYTE_LEN = 2;
static constexpr int32_t UTF8_THREE_BYTE_LEN = 3;
static constexpr int32_t UTF8_FOUR_BYTE_LEN = 4;
static constexpr size_t UTF8_FIRST_CONT_OFFSET = 1;
static constexpr size_t UTF8_SECOND_CONT_OFFSET = 2;
static constexpr size_t UTF8_THIRD_CONT_OFFSET = 3;

// nlohmann::json::dump() with default strict error_handler aborts on invalid UTF-8.
// Fuzz-generated strings can contain arbitrary bytes, so sanitize to valid UTF-8
// before feeding them into any struct that gets JSON-serialized.
static std::string SanitizeUtf8(const std::string &input)
{
    std::string out;
    auto len = input.length();
    out.reserve(len);
    for (size_t i = 0; i < len;) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        int32_t remaining = static_cast<int32_t>(len) - static_cast<int32_t>(i);
        if (c <= UTF8_ASCII_MAX) {
            out += static_cast<char>(c);
            ++i;
        } else if (c >= UTF8_TWO_BYTE_LEAD_MIN && c <= UTF8_TWO_BYTE_LEAD_MAX &&
                   remaining >= UTF8_TWO_BYTE_LEN &&
                   (static_cast<unsigned char>(input[i + UTF8_FIRST_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE) {
            out += input[i];
            out += input[i + UTF8_FIRST_CONT_OFFSET];
            i += UTF8_TWO_BYTE_LEN;
        } else if (c >= UTF8_THREE_BYTE_LEAD_MIN && c <= UTF8_THREE_BYTE_LEAD_MAX &&
                   remaining >= UTF8_THREE_BYTE_LEN &&
                   (static_cast<unsigned char>(input[i + UTF8_FIRST_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE &&
                   (static_cast<unsigned char>(input[i + UTF8_SECOND_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE) {
            out += input[i];
            out += input[i + UTF8_FIRST_CONT_OFFSET];
            out += input[i + UTF8_SECOND_CONT_OFFSET];
            i += UTF8_THREE_BYTE_LEN;
        } else if (c >= UTF8_FOUR_BYTE_LEAD_MIN && c <= UTF8_FOUR_BYTE_LEAD_MAX &&
                   remaining >= UTF8_FOUR_BYTE_LEN &&
                   (static_cast<unsigned char>(input[i + UTF8_FIRST_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE &&
                   (static_cast<unsigned char>(input[i + UTF8_SECOND_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE &&
                   (static_cast<unsigned char>(input[i + UTF8_THIRD_CONT_OFFSET]) &
                   UTF8_CONTINUATION_MASK) == UTF8_CONTINUATION_VALUE) {
            out += input[i];
            out += input[i + UTF8_FIRST_CONT_OFFSET];
            out += input[i + UTF8_SECOND_CONT_OFFSET];
            out += input[i + UTF8_THIRD_CONT_OFFSET];
            i += UTF8_FOUR_BYTE_LEN;
        } else {
            out += '_';
            ++i;
        }
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
