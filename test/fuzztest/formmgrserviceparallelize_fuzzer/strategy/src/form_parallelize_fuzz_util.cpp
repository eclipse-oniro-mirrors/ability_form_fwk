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

#include "../include/form_parallelize_fuzz_util.h"
#include "../include/form_constants_fuzzer.h"

using namespace OHOS::FuzzerConstants;

namespace OHOS {
namespace AppExecFwk {
sptr<IRemoteObject> FormParallelizeFuzzUtil::GetMockRemoteObject()
{
    return nullptr;
}

// Helper functions to fill structs with fuzzed data
void FormParallelizeFuzzUtil::FillFormJsInfo(FuzzedDataProvider &provider, FormJsInfo &formInfo)
{
    formInfo.formId = provider.ConsumeIntegral<int64_t>();
    formInfo.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.formTempFlag = provider.ConsumeBool();
    formInfo.jsFormCodePath = provider.ConsumeRandomLengthString(NUMBER_128);
    formInfo.formData = provider.ConsumeRandomLengthString(NUMBER_256);
    formInfo.formSrc = provider.ConsumeRandomLengthString(NUMBER_128);
    formInfo.formWindow.designWidth = provider.ConsumeIntegral<int32_t>();
    formInfo.formWindow.autoDesignWidth = provider.ConsumeBool();
    formInfo.versionCode = provider.ConsumeIntegral<uint32_t>();
    formInfo.versionName = provider.ConsumeRandomLengthString(NUMBER_32);
    formInfo.compatibleVersion = provider.ConsumeIntegral<uint32_t>();
    formInfo.type = static_cast<FormType>(provider.ConsumeIntegralInRange<int32_t>(0, NUMBER_2));
    formInfo.uiSyntax = static_cast<FormType>(provider.ConsumeIntegralInRange<int32_t>(0, NUMBER_2));
    formInfo.isDynamic = provider.ConsumeBool();
    formInfo.transparencyEnabled = provider.ConsumeBool();
}

void FormParallelizeFuzzUtil::FillRunningFormInfo(FuzzedDataProvider &provider, RunningFormInfo &formInfo)
{
    formInfo.formId = provider.ConsumeIntegral<int64_t>();
    formInfo.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.description = provider.ConsumeRandomLengthString(NUMBER_128);
    formInfo.dimension = provider.ConsumeIntegral<int32_t>();
    formInfo.hostBundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    formInfo.formLocation = static_cast<Constants::FormLocation>(provider.ConsumeIntegralInRange<int32_t>(0, NUMBER_3));
    formInfo.formVisiblity = static_cast<FormVisibilityType>(provider.ConsumeIntegralInRange<int32_t>(0, NUMBER_2));
    formInfo.formUsageState = static_cast<FormUsageState>(provider.ConsumeIntegralInRange<int32_t>(0, 1));
    formInfo.appIndex = provider.ConsumeIntegral<int32_t>();
    formInfo.userId = provider.ConsumeIntegral<int32_t>();
}

void FormParallelizeFuzzUtil::FillFormProviderData(FuzzedDataProvider &provider, FormProviderData &data)
{
    std::string jsonStr = "{\"key\":\"" + provider.ConsumeRandomLengthString(NUMBER_32) + "\"}";
    data = FormProviderData(jsonStr);
}

void FormParallelizeFuzzUtil::FillFormInfoFilter(FuzzedDataProvider &provider, FormInfoFilter &filter)
{
    filter.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    filter.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    size_t dimCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < dimCount; ++i) {
        filter.supportDimensions.push_back(provider.ConsumeIntegral<int32_t>());
    }
    size_t shapeCount = provider.ConsumeIntegralInRange<size_t>(0, 8);
    for (size_t i = 0; i < shapeCount; ++i) {
        filter.supportShapes.push_back(provider.ConsumeIntegral<int32_t>());
    }
}

void FormParallelizeFuzzUtil::FillFormStateInfo(FuzzedDataProvider &provider, FormStateInfo &stateInfo)
{
    // Want is already filled by default constructor
    stateInfo.state = static_cast<FormState>(provider.ConsumeIntegralInRange<int32_t>(0, NUMBER_2));
}

void FormParallelizeFuzzUtil::FillFormShareInfo(FuzzedDataProvider &provider, FormShareInfo &info)
{
    info.formId = provider.ConsumeIntegral<int64_t>();
    info.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.formTempFlag = provider.ConsumeBool();
    info.dimensionId = provider.ConsumeIntegral<int32_t>();
    info.deviceId = provider.ConsumeRandomLengthString(NUMBER_64);
    info.isFreeInstall = provider.ConsumeBool();
}

void FormParallelizeFuzzUtil::FillFormLockInfo(FuzzedDataProvider &provider, FormLockInfo &info)
{
    info.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.userId = provider.ConsumeIntegral<int32_t>();
    info.lock = provider.ConsumeBool();
}

void FormParallelizeFuzzUtil::FillFormMajorInfo(FuzzedDataProvider &provider, FormMajorInfo &info)
{
    info.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    info.dimension = provider.ConsumeIntegral<int32_t>();
}

void FormParallelizeFuzzUtil::FillFormInstancesFilter(FuzzedDataProvider &provider, FormInstancesFilter &filter)
{
    filter.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    filter.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    filter.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    filter.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    filter.isUnusedIncluded = provider.ConsumeBool();
}

void FormParallelizeFuzzUtil::FillRectInfo(FuzzedDataProvider &provider, Rect& rect)
{
    rect.left = provider.ConsumeFloatingPoint<double>();
    rect.top = provider.ConsumeFloatingPoint<double>();
    rect.width = provider.ConsumeFloatingPoint<double>();
    rect.height = provider.ConsumeFloatingPoint<double>();
}

void FormParallelizeFuzzUtil::FillOverflowInfo(FuzzedDataProvider &provider, OverflowInfo& overflowInfo)
{
    overflowInfo.area.left = provider.ConsumeFloatingPoint<double>();
    overflowInfo.area.top = provider.ConsumeFloatingPoint<double>();
    overflowInfo.area.width = provider.ConsumeFloatingPoint<double>();
    overflowInfo.area.height = provider.ConsumeFloatingPoint<double>();
    overflowInfo.duration = provider.ConsumeIntegral<int32_t>();
    overflowInfo.useDefaultAnimation = provider.ConsumeBool();
}

void FormParallelizeFuzzUtil::FillTemplateFormDetailInfo(FuzzedDataProvider &provider,
    TemplateFormDetailInfo& templateFormDetailInfo)
{
    templateFormDetailInfo.bundleName = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.moduleName = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.abilityName = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.formName = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.dimension = provider.ConsumeIntegral<int32_t>();
    templateFormDetailInfo.detailId = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.displayName = provider.ConsumeRandomLengthString(NUMBER_64);
    templateFormDetailInfo.description = provider.ConsumeRandomLengthString(NUMBER_64);
}
} // namespace AppExecFwk
} // namespace OHOS