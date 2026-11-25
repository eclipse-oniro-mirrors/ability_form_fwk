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

#include "formdataadaptersix_fuzzer.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_data_adapter.h"
#include "data_center/form_data_mgr.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_info.h"
#include "form_major_info.h"
#include "form_provider_data.h"
#include "form_provider_info.h"
#include "form_record_filter.h"
#include "form_supply_stub.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "want.h"
#include "want_params.h"
#include "ffrt.h"
#include "rdb_helper.h"

extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
}

// The stub allocator does not return storage inside a real ffrt task, so
// ffrt_submit_base must be stubbed as well to avoid heap corruption.
extern "C" void ffrt_submit_base(ffrt_function_header_t* f, const ffrt_deps_t* inDeps,
    const ffrt_deps_t* outDeps, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
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

// Interpose GetRdbStore to avoid opening a real store whose async threads
// outlive the fuzzer and race with rdb's static teardown at exit.
namespace OHOS {
namespace NativeRdb {
std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode)
{
    errCode = E_ERROR;
    return nullptr;
}
} // namespace NativeRdb
} // namespace OHOS

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 128;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DATA_SIZE = 1024;
constexpr int32_t MAX_CONDITION_TYPE = 10;
constexpr int32_t MAX_PID = 100000;
constexpr int32_t MIN_PID = 0;

// High-32-bits-set formId so FindMatchedFormId returns it directly (L1911-1912),
// enabling ValidateAndGetFormRecord to reach GetFormRecord success (L106).
constexpr int64_t SEED_FORM_ID = 0x100000001LL;
constexpr int64_t SEED_FORM_ID_2 = 0x100000002LL;
// Different high-32-bits formId, NOT seeded in formRecords_, so
// FindMatchedFormId returns it but GetFormRecord fails -> NOT_EXIST_ID branch.
constexpr int64_t UNSEEDED_FORM_ID = 0x200000003LL;
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 10000;
constexpr const char* TEST_BUNDLE = "com.test.dataadapter.six";
constexpr const char* TEST_MODULE = "testModule";
constexpr const char* TEST_ABILITY = "testAbility";
constexpr const char* TEST_FORM_NAME = "testForm";

// Non-null IRemoteObject stub for callerToken. Overrides the pure virtual
// methods from IFormSupply so IPC dispatch does not crash.
class FormSupplyStubFuzzTest : public FormSupplyStub {
public:
    FormSupplyStubFuzzTest() = default;
    virtual ~FormSupplyStubFuzzTest() = default;
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override { return 0; }
    int OnEventHandle(const Want &want) override { return 0; }
    int OnAcquireStateResult(FormState state, const std::string &provider,
        const Want &wantArg, const Want &want) override { return 0; }
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode,
        const bool &result) override {}
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override { return 0; }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override { return 0; }
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams,
        int64_t requestCode) override { return 0; }
};

std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    return result.empty() ? "default" : result;
}

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    std::string bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    std::string abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    if (!bundleName.empty() && !abilityName.empty()) {
        want.SetElementName(bundleName, abilityName);
    }
    want.SetAction(GenerateSafeString(fdp, MAX_LENGTH));
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

FormProviderData GenerateFormProviderData(FuzzedDataProvider *fdp)
{
    std::string data = fdp->ConsumeRandomLengthString(MAX_DATA_SIZE);
    if (data.empty()) {
        data = "{}";
    }
    FormProviderData formProviderData(data);
    return formProviderData;
}

std::vector<FormDataProxy> GenerateFormDataProxies(FuzzedDataProvider *fdp)
{
    std::vector<FormDataProxy> proxies;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        std::string bundleName = GenerateSafeString(fdp, MAX_LENGTH);
        std::string abilityName = GenerateSafeString(fdp, MAX_LENGTH);
        if (!bundleName.empty() && !abilityName.empty()) {
            FormDataProxy proxy(bundleName, abilityName);
            proxies.push_back(proxy);
        }
    }
    return proxies;
}

FormProviderInfo GenerateFormProviderInfo(FuzzedDataProvider *fdp)
{
    FormProviderInfo formProviderInfo;
    formProviderInfo.SetFormData(GenerateFormProviderData(fdp));
    formProviderInfo.SetSupportMoreImages(fdp->ConsumeBool());
    formProviderInfo.SetUpgradeFlg(fdp->ConsumeBool());
    formProviderInfo.SetFormDataProxies(GenerateFormDataProxies(fdp));
    return formProviderInfo;
}

// Seed a FormRecord into FormDataMgr::formRecords_ so that
// FindMatchedFormId + GetFormRecord succeed (ValidateAndGetFormRecord happy path).
FormRecord MakeSeededRecord(int64_t formId, const std::string &bundleName)
{
    FormRecord r;
    r.formId = formId;
    r.bundleName = bundleName;
    r.moduleName = TEST_MODULE;
    r.abilityName = TEST_ABILITY;
    r.formName = TEST_FORM_NAME;
    r.userId = TEST_USER_ID;
    r.providerUserId = TEST_USER_ID;
    r.uid = TEST_CALLING_UID;
    r.specification = 1;
    r.isEnableUpdate = true;
    r.formTempFlag = false;
    r.updateDuration = 0;
    r.isDataProxy = false;
    r.isSystemApp = false;
    r.needRefresh = false;
    r.isDynamic = true;
    r.uiSyntax = FormType::ETS;
    r.formLocation = Constants::FormLocation::OTHER;
    r.versionCode = 1;
    r.versionName = "1.0.0";
    r.compatibleVersion = 1;
    r.type = FormType::ETS;
    r.transparencyEnabled = false;
    r.privacyLevel = 0;
    r.enableForm = true;
    r.lockForm = false;
    return r;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormDataAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();

    // --- Seed formRecords_ for ValidateAndGetFormRecord success path ---
    dataMgr.formRecords_[SEED_FORM_ID] = MakeSeededRecord(SEED_FORM_ID, TEST_BUNDLE);
    dataMgr.formRecords_[SEED_FORM_ID_2] = MakeSeededRecord(SEED_FORM_ID_2, TEST_BUNDLE);

    // --- 1. UpdateForm(FormProviderInfo) overload (L151-167) ---
    // Covers: ValidateAndGetFormRecord success -> UpdateSupportMoreImagesAndDB
    //   + RefreshAndUpdateProxies(formProviderInfo.GetFormData(), GetFormProxies()).
    {
        int32_t callingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        FormProviderInfo providerInfo = GenerateFormProviderInfo(fdp);
        adapter.UpdateForm(SEED_FORM_ID, callingUid, providerInfo);
    }

    // --- 2. UpdateForm(FormProviderInfo) with formId<=0 -> ValidateAndGetFormRecord error ---
    {
        int32_t callingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        FormProviderInfo providerInfo = GenerateFormProviderInfo(fdp);
        adapter.UpdateForm(0, callingUid, providerInfo);
    }

    // --- 3. UpdateFormCrossBundle (L169-190) ---
    // Covers: ValidateAndGetFormRecord success -> RequestRefresh(TYPE_DATA) with
    //   data.callingUid = formRecord.uid (cross-bundle uid substitution).
    {
        int32_t callingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        FormProviderData providerData = GenerateFormProviderData(fdp);
        adapter.UpdateFormCrossBundle(SEED_FORM_ID_2, callingUid, providerData);
    }

    // --- 4. UpdateFormCrossBundle with invalid formId -> ValidateAndGetFormRecord error ---
    {
        int32_t callingUid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        FormProviderData providerData = GenerateFormProviderData(fdp);
        adapter.UpdateFormCrossBundle(-1, callingUid, providerData);
    }

    // --- 5. UpdateFormsWithReminderAgent (L192-225) ---
    // Covers: GetFormRecord(bundleName, formRecords, userId) success (seeded) ->
    //   loop body -> GetFormsInfoByRecord fail/success + enableReminderAgentRefresh
    //   check -> BatchRequestRefresh or empty-batch early return.
    {
        Want want = GenerateWant(fdp);
        adapter.UpdateFormsWithReminderAgent(TEST_BUNDLE, TEST_USER_ID, want);
    }

    // --- 6. UpdateFormsWithReminderAgent with unseeded bundle -> not found early return ---
    {
        std::string unknownBundle = GenerateSafeString(fdp, MAX_LENGTH);
        Want want = GenerateWant(fdp);
        adapter.UpdateFormsWithReminderAgent(unknownBundle, TEST_USER_ID, want);
    }

    // --- 7. UpdateFormByCondition(type, userId) overload (L766-805) ---
    // Covers: valid type + userId>=0 -> GetFormRecordByCondition;
    //   invalid type -> CONDITION_TYPE_MAP miss (L773-774).
    //   The userId<0 + CONDITION_ACCOUNT error branch is covered by block 8 below.
    {
        int32_t type = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_CONDITION_TYPE);
        int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(0, TEST_USER_ID);
        adapter.UpdateFormByCondition(type, userId);
    }

    // --- 8. UpdateFormByCondition(type, userId) with CONDITION_ACCOUNT + negative userId ---
    // Covers: L769-771 userId<0 + CONDITION_ACCOUNT -> ERR_APPEXECFWK_FORM_COMMON_CODE.
    {
        adapter.UpdateFormByCondition(Constants::CONDITION_ACCOUNT, -1);
    }

    // --- 9. ValidateAndGetFormRecord (private, L98-111) ---
    // Covers: formId<=0 -> INVALID_PARAM; formId>0 not found -> NOT_EXIST_ID;
    //   formId>0 found -> ERR_OK.
    {
        int64_t matchedFormId = 0;
        FormRecord formRecord;
        // formId<=0 branch
        adapter.ValidateAndGetFormRecord(0, matchedFormId, formRecord);
        // not-found branch (unseeded high-bits id)
        adapter.ValidateAndGetFormRecord(UNSEEDED_FORM_ID, matchedFormId, formRecord);
        // success branch (seeded)
        adapter.ValidateAndGetFormRecord(SEED_FORM_ID, matchedFormId, formRecord);
    }

    // --- 10. RefreshAndUpdateProxies (private, L113-133) ---
    // Covers: RequestRefresh(TYPE_DATA) + formDataProxies empty/non-empty
    //   -> UpdateSubscribeFormData branch.
    {
        FormRecord record = MakeSeededRecord(SEED_FORM_ID, TEST_BUNDLE);
        FormProviderData providerData = GenerateFormProviderData(fdp);
        std::vector<FormDataProxy> proxies = GenerateFormDataProxies(fdp);
        adapter.RefreshAndUpdateProxies(SEED_FORM_ID, TEST_CALLING_UID, record, providerData, proxies);
    }

    // --- 11. HandleUpdateFormFlag (private, L333-354) ---
    // Covers: empty formIds -> INVALID_PARAM; null token -> INVALID_PARAM;
    //   non-null token + non-empty formIds -> UpdateHostFormFlag path.
    {
        // empty formIds branch
        std::vector<int64_t> emptyIds;
        adapter.HandleUpdateFormFlag(emptyIds, nullptr, true, false);

        // null token branch
        std::vector<int64_t> ids = GenerateFormIds(fdp);
        adapter.HandleUpdateFormFlag(ids, nullptr, fdp->ConsumeBool(), fdp->ConsumeBool());

        // non-null token branch
        sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
        if (callerToken != nullptr) {
            std::vector<int64_t> ids2 = GenerateFormIds(fdp);
            adapter.HandleUpdateFormFlag(ids2, callerToken, fdp->ConsumeBool(), fdp->ConsumeBool());
        }
    }

    // --- 12. GetUpdateDurationFromAdditionalInfo (private, L891-902) ---
    // Covers: empty string -> 0; non-empty without formUpdateLevel -> ParseFormUpdateLevels
    //   empty -> 0; with "formUpdateLevel:N" -> N * TIME_CONVERSION.
    {
        adapter.GetUpdateDurationFromAdditionalInfo("");
        adapter.GetUpdateDurationFromAdditionalInfo(GenerateSafeString(fdp, MAX_LENGTH));
        adapter.GetUpdateDurationFromAdditionalInfo("formUpdateLevel:2;other:data");
        adapter.GetUpdateDurationFromAdditionalInfo("formUpdateLevel:0");  // below MIN_CONFIG_DURATION
    }

    // --- 13. CheckUIAbilityContext (private, L680-700) ---
    // Covers: GetAppMgr returns null in fuzz env -> false branch; also exercises
    //   ResetCallingIdentity/SetCallingIdentity IPC paths with a fuzz-derived pid.
    {
        pid_t pid = static_cast<pid_t>(fdp->ConsumeIntegralInRange<int32_t>(MIN_PID, MAX_PID));
        adapter.CheckUIAbilityContext(pid);
    }

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
