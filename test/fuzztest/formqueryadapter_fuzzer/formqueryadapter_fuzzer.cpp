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

#include "formqueryadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr/form_query_adapter.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_USER_ID = 100;
constexpr int32_t MIN_USER_ID = 0;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetAction(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormQueryAdapter::GetInstance();

    // Fuzz GetAllFormsInfo
    std::vector<FormInfo> allFormInfos;
    adapter.GetAllFormsInfo(allFormInfos);

    // Fuzz GetFormsInfoByApp
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> appFormInfos;
    adapter.GetFormsInfoByApp(bundleName, appFormInfos);

    // Fuzz GetFormsInfoByModule
    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> moduleFormInfos;
    adapter.GetFormsInfoByModule(bundleName, moduleName, moduleFormInfos);

    // Fuzz GetFormsInfoByFilter
    FormInfoFilter filter;
    filter.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    filter.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> filterFormInfos;
    adapter.GetFormsInfoByFilter(filter, filterFormInfos);

    // Fuzz GetFormInstanceById
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormInstance formInstance;
    adapter.GetFormInstanceById(formId, formInstance);

    // Fuzz GetFormInstanceById with isUnusedIncluded
    int64_t formIdUnused = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    bool isUnusedIncluded = fdp->ConsumeBool();
    FormInstance formInstanceUnused;
    adapter.GetFormInstanceById(formIdUnused, isUnusedIncluded, formInstanceUnused);

    // Fuzz GetRunningFormInfos
    std::vector<RunningFormInfo> runningFormInfos;
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.GetRunningFormInfos(isUnusedIncluded, runningFormInfos, userId);

    // Fuzz GetAllTemplateFormsInfo
    std::vector<FormInfo> templateFormInfos;
    adapter.GetAllTemplateFormsInfo(templateFormInfos);

    // Fuzz GetTemplateFormsInfoByApp
    std::string templateBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> templateAppFormInfos;
    adapter.GetTemplateFormsInfoByApp(templateBundleName, templateAppFormInfos);

    // Fuzz GetTemplateFormsInfoByModule
    std::string templateModuleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<FormInfo> templateModuleFormInfos;
    adapter.GetTemplateFormsInfoByModule(templateBundleName, templateModuleName, templateModuleFormInfos);

    // Fuzz GetFormsCount
    bool isTempFormFlag = fdp->ConsumeBool();
    int32_t formCount = 0;
    adapter.GetFormsCount(isTempFormFlag, formCount);

    // Fuzz GetHostFormsCount
    std::string hostBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t hostFormCount = 0;
    adapter.GetHostFormsCount(hostBundleName, hostFormCount);

    // Fuzz GetRunningFormInfosByBundleName
    std::string runningBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bool runningIsUnusedIncluded = fdp->ConsumeBool();
    std::vector<RunningFormInfo> bundleRunningFormInfos;
    adapter.GetRunningFormInfosByBundleName(runningBundleName, runningIsUnusedIncluded, bundleRunningFormInfos);

    // Fuzz GetFormInstancesByFilter
    FormInstancesFilter instancesFilter;
    std::vector<FormInstance> formInstances;
    adapter.GetFormInstancesByFilter(instancesFilter, formInstances);

    // Fuzz AcquireFormState
    Want stateWant = GenerateWant(fdp);
    sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    adapter.AcquireFormState(stateWant, callerToken, stateInfo);

    // Fuzz AcquireFormData
    int64_t dataFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int64_t requestCode = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    AAFwk::WantParams formData;
    adapter.AcquireFormData(dataFormId, requestCode, callerToken, formData);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
