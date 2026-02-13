/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formhostrecord_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "form_host/form_host_record.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t MAX_STRING_SIZE = 20;

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}

/**
 * @brief Generate fuzzed FormRecord for testing
 */
FormRecord GenerateFuzzedFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegral<int64_t>();
    record.bundleName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.moduleName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.abilityName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.formName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.specification = fdp->ConsumeIntegral<int32_t>();
    record.isEnableUpdate = fdp->ConsumeBool();
    record.isVisible = fdp->ConsumeBool();
    return record;
}

/**
 * @brief Test FormHostRecord basic APIs
 */
void TestFormHostRecordBasicAPIs(const char* data, size_t size)
{
    FormHostRecord formHostRecord;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));

    // Test form id management
    formHostRecord.AddForm(formId);
    formHostRecord.DelForm(formId);
    formHostRecord.Contains(formId);

    // Test refresh control
    bool flag = *data % 2;
    formHostRecord.SetEnableRefresh(formId, flag);
    formHostRecord.IsEnableRefresh(formId);

    // Test update control
    bool enable = *data % 2;
    formHostRecord.SetEnableUpdate(formId, enable);
    formHostRecord.IsEnableUpdate(formId);

    // Test need refresh control
    formHostRecord.SetNeedRefresh(formId, flag);
    formHostRecord.IsNeedRefresh(formId);

    // Test getters
    formHostRecord.GetFormHostClient();

    // Test OnAcquire and OnUpdate
    int64_t id = static_cast<int64_t>(GetU32Data(data));
    FormRecord record;
    formHostRecord.OnAcquire(id, record);
    formHostRecord.OnUpdate(id, record);

    // Test OnFormUninstalled
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    formHostRecord.OnFormUninstalled(formIds);

    // Test OnAcquireState
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    formHostRecord.OnAcquireState(state, want);

    // Test CleanResource
    formHostRecord.CleanResource();

    // Test setters
    int callerUid = static_cast<int>(GetU32Data(data));
    formHostRecord.SetCallerUid(callerUid);
    sptr<IRemoteObject> formHostClient = nullptr;
    formHostRecord.SetFormHostClient(formHostClient);
    std::shared_ptr<FormHostCallback> formHostCallback = nullptr;
    formHostRecord.SetCallback(formHostCallback);

    // Test death recipient
    formHostRecord.GetDeathRecipient();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formHostRecord.SetDeathRecipient(deathRecipient);
    formHostRecord.AddDeathRecipient(deathRecipient);

    // Test CreateRecord
    FormItemInfo info;
    sptr<IRemoteObject> callback = nullptr;
    int callingUid = static_cast<int>(GetU32Data(data));
    formHostRecord.CreateRecord(info, callback, callingUid);

    // Test host bundle name
    formHostRecord.GetHostBundleName();
    std::string hostBundleName(data, size);
    formHostRecord.SetHostBundleName(hostBundleName);

    // Test IsEmpty
    formHostRecord.IsEmpty();
}

/**
 * @brief Test FormHostRecord extended APIs with FuzzedDataProvider
 */
void TestFormHostRecordExtendedAPIs(FuzzedDataProvider *fdp)
{
    FormHostRecord formHostRecord;

    // Add some forms
    int64_t formId1 = fdp->ConsumeIntegral<int64_t>();
    int64_t formId2 = fdp->ConsumeIntegral<int64_t>();
    formHostRecord.AddForm(formId1);
    formHostRecord.AddForm(formId2);

    // Test GetFormsCount
    formHostRecord.GetFormsCount();

    // Test OnAcquireFormData
    AAFwk::WantParams wantParams;
    int64_t requestCode = fdp->ConsumeIntegral<int64_t>();
    formHostRecord.OnAcquireFormData(wantParams, requestCode);

    // Test OnRecycleForms
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    AAFwk::Want want;
    formHostRecord.OnRecycleForms(formIds, want);

    // Test OnEnableForms
    bool enable = fdp->ConsumeBool();
    formHostRecord.OnEnableForms(formIds, enable);

    // Test OnLockForms
    bool lock = fdp->ConsumeBool();
    formHostRecord.OnLockForms(formIds, lock);

    // Test OnCheckForms
    formHostRecord.OnCheckForms(formIds);

    // Test GetForms
    std::vector<int64_t> retrievedFormIds;
    formHostRecord.GetForms(retrievedFormIds);

    // Test OnDueControlForms
    bool isDisablePolicy = fdp->ConsumeBool();
    bool isControl = fdp->ConsumeBool();
    formHostRecord.OnDueControlForms(formIds, isDisablePolicy, isControl);

    // Test transparent form color operations
    int64_t transparentFormId = fdp->ConsumeIntegral<int64_t>();
    formHostRecord.ContainsTransparentForm(transparentFormId);

    std::string transparencyColor = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    formHostRecord.SetTransparentFormColor(transparentFormId, transparencyColor);

    formHostRecord.GetTransparentFormColor(transparentFormId);

    formHostRecord.DeleteTransparentFormColor(transparentFormId);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    // Test basic APIs with original data
    TestFormHostRecordBasicAPIs(data, size);

    // Test extended APIs with FuzzedDataProvider
    FuzzedDataProvider fdp(reinterpret_cast<const uint8_t*>(data), size);
    TestFormHostRecordExtendedAPIs(&fdp);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
