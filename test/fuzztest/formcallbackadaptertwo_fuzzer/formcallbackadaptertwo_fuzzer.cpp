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

#include "formcallbackadaptertwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <unordered_map>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_callback_adapter.h"
#undef private
#undef protected

#include "form_custom_config.h"
#include "form_instance.h"
#include "form_record_filter.h"
#include "form_publish_interceptor_interface.h"
#include "template_form_detail_info.h"
#include "want.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_STATE = 10;
constexpr int32_t MIN_STATE = 0;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetAction(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

std::vector<int64_t> GenerateFormIds(FuzzedDataProvider *fdp)
{
    std::vector<int64_t> formIds;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        formIds.push_back(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    }
    return formIds;
}

OverflowInfo GenerateOverflowInfo(FuzzedDataProvider *fdp)
{
    OverflowInfo overflowInfo;
    overflowInfo.area.left = fdp->ConsumeFloatingPoint<float>();
    overflowInfo.area.top = fdp->ConsumeFloatingPoint<float>();
    overflowInfo.area.width = fdp->ConsumeFloatingPoint<float>();
    overflowInfo.area.height = fdp->ConsumeFloatingPoint<float>();
    overflowInfo.duration = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_STATE);
    overflowInfo.useDefaultAnimation = fdp->ConsumeBool();
    return overflowInfo;
}

TemplateFormDetailInfo GenerateTemplateFormDetailInfo(FuzzedDataProvider *fdp)
{
    TemplateFormDetailInfo info;
    info.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_ID, MAX_FORM_ID);
    info.detailId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.displayName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.description = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    return info;
}

std::vector<TemplateFormDetailInfo> GenerateTemplateFormDetailInfos(FuzzedDataProvider *fdp)
{
    std::vector<TemplateFormDetailInfo> infos;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        infos.push_back(GenerateTemplateFormDetailInfo(fdp));
    }
    return infos;
}

FormCustomConfig GenerateFormCustomConfig(FuzzedDataProvider *fdp)
{
    FormCustomConfig config;
    config.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.relatedBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    config.isShowInFormCenter = fdp->ConsumeBool();
    config.isRepeatAdditionSupported = fdp->ConsumeBool();
    return config;
}

std::vector<FormCustomConfig> GenerateFormCustomConfigs(FuzzedDataProvider *fdp)
{
    std::vector<FormCustomConfig> configs;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        configs.push_back(GenerateFormCustomConfig(fdp));
    }
    return configs;
}

FormRecordFilter GenerateFormRecordFilter(FuzzedDataProvider *fdp)
{
    FormRecordFilter filter;
    filter.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    return filter;
}

std::vector<FormRecordFilter> GenerateFormRecordFilters(FuzzedDataProvider *fdp)
{
    std::vector<FormRecordFilter> filters;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        filters.push_back(GenerateFormRecordFilter(fdp));
    }
    return filters;
}

PublishFormCrossBundleInfo GeneratePublishFormCrossBundleInfo(FuzzedDataProvider *fdp)
{
    PublishFormCrossBundleInfo info;
    info.callerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.targetBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    info.targetTemplateFormDetailId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    return info;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormCallbackAdapter::GetInstance();

    // Fuzz RegisterOverflowProxy / UnregisterOverflowProxy
    sptr<IRemoteObject> overflowCallerToken = nullptr;
    adapter.RegisterOverflowProxy(overflowCallerToken);
    adapter.UnregisterOverflowProxy();

    // Fuzz RequestOverflow
    int64_t overflowFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t overflowCallingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    OverflowInfo overflowInfo = GenerateOverflowInfo(fdp);
    bool isOverflow = fdp->ConsumeBool();
    adapter.RequestOverflow(overflowFormId, overflowCallingUid, overflowInfo, isOverflow);

    // Fuzz RegisterChangeSceneAnimationStateProxy / UnregisterChangeSceneAnimationStateProxy
    sptr<IRemoteObject> sceneAnimationToken = nullptr;
    adapter.RegisterChangeSceneAnimationStateProxy(sceneAnimationToken);
    adapter.UnregisterChangeSceneAnimationStateProxy();

    // Fuzz ChangeSceneAnimationState
    int64_t sceneFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t sceneCallingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    int32_t state = fdp->ConsumeIntegralInRange<int32_t>(MIN_STATE, MAX_STATE);
    adapter.ChangeSceneAnimationState(sceneFormId, sceneCallingUid, state);

    // Fuzz RegisterGetFormRectProxy / UnregisterGetFormRectProxy
    sptr<IRemoteObject> formRectToken = nullptr;
    adapter.RegisterGetFormRectProxy(formRectToken);
    adapter.UnregisterGetFormRectProxy();

    // Fuzz GetFormRect
    int64_t formRectFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t formRectCallingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    Rect rect;
    adapter.GetFormRect(formRectFormId, formRectCallingUid, rect);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
