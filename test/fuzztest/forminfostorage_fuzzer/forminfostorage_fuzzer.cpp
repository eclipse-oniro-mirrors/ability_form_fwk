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

#include "forminfostorage_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/form_info_storage.h"
#undef private
#undef protected
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

using namespace OHOS;
using namespace OHOS::AAFwk;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = -10000;

// Sanitize fuzz bytes to safe ASCII for fields serialized by FormInfo::to_json
// → nlohmann::json::dump(), which aborts on invalid UTF-8 with the default
// strict error handler.
std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength = MAX_LENGTH)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safeResult;
    for (char c : result) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' ||
            c == '.' || c == '/' || c == ':') {
            safeResult += c;
        } else {
            safeResult += '_';
        }
    }
    return safeResult.empty() ? "default" : safeResult;
}

AppExecFwk::FormInfo CreateFormInfo(FuzzedDataProvider *fdp)
{
    AppExecFwk::FormInfo formInfo;
    formInfo.name = GenerateSafeString(fdp);
    formInfo.bundleName = GenerateSafeString(fdp);
    formInfo.moduleName = GenerateSafeString(fdp);
    formInfo.abilityName = GenerateSafeString(fdp);
    formInfo.description = GenerateSafeString(fdp);
    formInfo.formConfigAbility = GenerateSafeString(fdp);
    formInfo.updateEnabled = fdp->ConsumeBool();
    formInfo.updateDuration = fdp->ConsumeIntegral<uint32_t>();
    formInfo.scheduledUpdateTime = GenerateSafeString(fdp);
    formInfo.formVisibleNotify = fdp->ConsumeBool();
    formInfo.relatedBundleName = GenerateSafeString(fdp);
    formInfo.jsComponentName = GenerateSafeString(fdp);
    formInfo.isDynamic = fdp->ConsumeBool();
    formInfo.isStatic = fdp->ConsumeBool();
    formInfo.isTemplateForm = fdp->ConsumeBool();
    formInfo.versionCode = fdp->ConsumeIntegral<uint32_t>();
    return formInfo;
}

AppExecFwk::FormInfoFilter CreateFormInfoFilter(FuzzedDataProvider *fdp)
{
    AppExecFwk::FormInfoFilter filter;
    filter.bundleName = GenerateSafeString(fdp);
    filter.moduleName = GenerateSafeString(fdp);
    int32_t numShapes = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numShapes; i++) {
        filter.supportShapes.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    int32_t numDims = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numDims; i++) {
        filter.supportDimensions.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    return filter;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int32_t userId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    std::vector<AppExecFwk::FormInfo> formInfos;
    int32_t numFormInfos = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numFormInfos; i++) {
        formInfos.push_back(CreateFormInfo(fdp));
    }

    FormInfoStorage formInfoStorage(userId, formInfos);

    std::vector<AppExecFwk::FormInfo> resultFormInfos;
    formInfoStorage.GetAllFormsInfo(userId, resultFormInfos);

    resultFormInfos.clear();
    formInfoStorage.GetAllTemplateFormsInfo(userId, resultFormInfos);

    std::string moduleName = GenerateSafeString(fdp);
    resultFormInfos.clear();
    formInfoStorage.GetFormsInfoByModule(userId, moduleName, resultFormInfos);

    resultFormInfos.clear();
    formInfoStorage.GetTemplateFormsInfoByModule(userId, moduleName, resultFormInfos);

    resultFormInfos.clear();
    AppExecFwk::FormInfoFilter filter = CreateFormInfoFilter(fdp);
    formInfoStorage.GetFormsInfoByFilter(userId, filter, resultFormInfos);

    nlohmann::json jsonObject = formInfoStorage;
    std::string jsonString = jsonObject.dump();

    FormInfoStorage formInfoStorageFromJson;
    nlohmann::json parsedJson = nlohmann::json::parse(jsonString, nullptr, false);
    if (!parsedJson.is_discarded()) {
        from_json(parsedJson, formInfoStorageFromJson);
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
