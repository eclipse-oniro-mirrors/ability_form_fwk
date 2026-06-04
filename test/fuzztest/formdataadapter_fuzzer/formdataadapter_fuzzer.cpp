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

#include "formdataadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_data_adapter.h"
#undef private
#undef protected

#include "form_info.h"
#include "form_instance.h"
#include "form_major_info.h"
#include "form_provider_data.h"
#include "form_record_filter.h"
#include "want.h"
#include "want_params.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;

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

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    record.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, 23);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, 59);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.needRefresh = fdp->ConsumeBool();
    record.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegral<int32_t>());
    return record;
}

std::vector<FormRecord> GenerateFormRecords(FuzzedDataProvider *fdp)
{
    std::vector<FormRecord> records;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        records.push_back(GenerateFormRecord(fdp));
    }
    return records;
}

FormProviderData GenerateFormProviderData(FuzzedDataProvider *fdp)
{
    FormProviderData formProviderData(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return formProviderData;
}

std::vector<FormDataProxy> GenerateFormDataProxies(FuzzedDataProvider *fdp)
{
    std::vector<FormDataProxy> proxies;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        FormDataProxy proxy(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                            fdp->ConsumeRandomLengthString(MAX_LENGTH));
        proxies.push_back(proxy);
    }
    return proxies;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormDataAdapter::GetInstance();

    // Fuzz UpdateForm
    int64_t updateFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t callingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    FormProviderData formProviderData = GenerateFormProviderData(fdp);
    std::vector<FormDataProxy> formDataProxies = GenerateFormDataProxies(fdp);
    adapter.UpdateForm(updateFormId, callingUid, formProviderData, formDataProxies);

    // Fuzz RequestForm
    int64_t requestFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> callerToken = nullptr;
    Want requestWant = GenerateWant(fdp);
    adapter.RequestForm(requestFormId, callerToken, requestWant);

    // Fuzz UpdateFormSize (float version)
    int64_t sizeFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    float width = fdp->ConsumeFloatingPoint<float>();
    float height = fdp->ConsumeFloatingPoint<float>();
    float borderWidth = fdp->ConsumeFloatingPoint<float>();
    float formViewScale = fdp->ConsumeFloatingPoint<float>();
    adapter.UpdateFormSize(sizeFormId, width, height, borderWidth, formViewScale);

    // Fuzz UpdateFormSize (dimension version)
    int64_t dimFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t newDimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    Rect newRect;
    newRect.left = fdp->ConsumeFloatingPoint<float>();
    newRect.top = fdp->ConsumeFloatingPoint<float>();
    newRect.width = fdp->ConsumeFloatingPoint<float>();
    newRect.height = fdp->ConsumeFloatingPoint<float>();
    adapter.UpdateFormSize(dimFormId, newDimension, newRect);

    // Fuzz EnableUpdateForm
    std::vector<int64_t> enableFormIds = GenerateFormIds(fdp);
    sptr<IRemoteObject> enableCallerToken = nullptr;
    adapter.EnableUpdateForm(enableFormIds, enableCallerToken);

    // Fuzz DisableUpdateForm
    adapter.DisableUpdateForm(enableFormIds, enableCallerToken);

    // Fuzz BatchRefreshForms
    int32_t formRefreshType = fdp->ConsumeIntegralInRange<int32_t>(0, 10);
    adapter.BatchRefreshForms(formRefreshType);

    // Fuzz SetNextRefreshTime
    int64_t nextFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int64_t nextTime = fdp->ConsumeIntegral<int64_t>();
    adapter.SetNextRefreshTime(nextFormId, nextTime);

    // Fuzz UpdateFormRenderParam
    int64_t renderParamFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> renderCallerToken = nullptr;
    Want renderWant = GenerateWant(fdp);
    adapter.UpdateFormRenderParam(renderParamFormId, renderCallerToken, renderWant);

    // Fuzz UpdateFormLocation
    int64_t locationFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t formLocation = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
    bool isRequestPublishFormWithSnapshot = fdp->ConsumeBool();
    adapter.UpdateFormLocation(locationFormId, formLocation, isRequestPublishFormWithSnapshot);

    // Fuzz AcquireProviderFormInfoAsync
    FormItemInfo formItemInfo;
    WantParams wantParams;
    int64_t acquireFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.AcquireProviderFormInfoAsync(acquireFormId, formItemInfo, wantParams);

    // Fuzz ReAcquireProviderFormInfoAsync
    adapter.ReAcquireProviderFormInfoAsync(formItemInfo, wantParams);

    // Fuzz ReloadForms
    int32_t reloadNum = 0;
    std::vector<FormRecord> refreshForms = GenerateFormRecords(fdp);
    adapter.ReloadForms(reloadNum, refreshForms);

    // Fuzz OnNotifyRefreshForm
    int64_t notifyFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.OnNotifyRefreshForm(notifyFormId);

    // Fuzz UpdateFormByCondition
    int32_t conditionType = fdp->ConsumeIntegralInRange<int32_t>(0, 10);
    adapter.UpdateFormByCondition(conditionType);

    // Fuzz DelayRefreshFormsOnAppUpgrade
    std::vector<FormRecord> updatedForms = GenerateFormRecords(fdp);
    Want upgradeWant = GenerateWant(fdp);
    adapter.DelayRefreshFormsOnAppUpgrade(updatedForms, upgradeWant);

    // Fuzz AcquireProviderFormInfoByFormRecord
    FormRecord providerRecord = GenerateFormRecord(fdp);
    WantParams providerWantParams;
    adapter.AcquireProviderFormInfoByFormRecord(providerRecord, providerWantParams);

    // Fuzz ClearReconnectNum
    int64_t reconnectFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.ClearReconnectNum(reconnectFormId);

    // Fuzz IsDeleteCacheInUpgradeScene
    FormRecord upgradeRecord = GenerateFormRecord(fdp);
    adapter.IsDeleteCacheInUpgradeScene(upgradeRecord);

    // Fuzz DeleteInvalidFormCacheIfNeed
    adapter.DeleteInvalidFormCacheIfNeed();

    // Fuzz UpdateTimer
    FormRecord timerRecord = GenerateFormRecord(fdp);
    adapter.UpdateTimer(timerRecord.formId, timerRecord);

    // Fuzz UpdateReUpdateFormMap
    int64_t reUpdateFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.UpdateReUpdateFormMap(reUpdateFormId);

    // Fuzz SetReUpdateFormMap
    adapter.SetReUpdateFormMap(reUpdateFormId);

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