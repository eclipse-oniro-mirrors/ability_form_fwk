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

#include "formeventadapterfour_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#include "form_supply_stub.h"

#define private public
#define protected public
#include "form_mgr/form_event_adapter.h"
#include "data_center/form_data_mgr.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_host/form_host_record.h"
#include "want.h"
#include "ffrt.h"

// Interpose the parameter watcher registration that FormDataMgr triggers at
// init time. Its IPC-thread callback can submit ffrt tasks after the global
// scheduler is torn down at process exit (heap-use-after-free).
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

// Interpose ffrt_queue_submit_h so no ffrt task is ever enqueued. Enqueuing
// tasks spawns ffrt CPU workers whose threads still run when ffrt's static
// CPUWorkerGroup is torn down at exit (heap-use-after-free).
extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {

// Stub subclass of FormSupplyStub to obtain a non-null sptr<IRemoteObject> as
// callerToken, enabling coverage past the token early-return defense.
class FormSupplyStubFuzzTest : public FormSupplyStub {
public:
    FormSupplyStubFuzzTest() = default;
    virtual ~FormSupplyStubFuzzTest() = default;
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return 0;
    }
    int OnEventHandle(const Want &want) override
    {
        return 0;
    }
    int OnAcquireStateResult(FormState state, const std::string &provider,
        const Want &wantArg, const Want &want) override
    {
        return 0;
    }
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override
    {}
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return ERR_OK;
    }
};

// --- Constants ---
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t NUM_SCENARIOS = 6;

// Distinct formId bases per scenario to avoid singleton cross-contamination.
constexpr int64_t BASE_FORM_ID_A = 100;
constexpr int64_t BASE_FORM_ID_B = 200;
constexpr int64_t BASE_FORM_ID_C = 300;
constexpr int64_t BASE_FORM_ID_D = 400;
constexpr int64_t BASE_FORM_ID_E = 500;
constexpr int64_t BASE_FORM_ID_F = 600;

// MAX_NUMBER_OF_JS threshold from form_event_adapter.cpp (line 52).
constexpr int64_t MAX_NUMBER_OF_JS = 0x20000000000000;

// Invalid openType value (outside CardActionParamOpenType enum range 0-2).
constexpr int32_t INVALID_OPEN_TYPE = 3;

// --- Helper functions ---
std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safeResult;
    for (char c : result) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' || c == '.' || c == '/' || c == ':') {
            safeResult += c;
        } else {
            safeResult += '_';
        }
    }
    return safeResult.empty() ? "default" : safeResult;
}

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    record.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    record.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    record.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    record.formName = GenerateSafeString(fdp, MAX_LENGTH);
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_HOUR);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_MINUTE);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.formLocation = static_cast<Constants::FormLocation>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION));
    return record;
}

// Seed a form record into FormDataMgr singleton's formRecords_ map.
void SeedFormRecord(int64_t formId, const FormRecord &record)
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.formRecords_[formId] = record;
}

// Remove a seeded form record.
void ClearFormRecord(int64_t formId)
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.formRecords_.erase(formId);
}

// Seed a host record into FormDataMgr singleton's clientRecords_ vector.
void SeedHostRecord(const FormHostRecord &hostRecord)
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.clientRecords_.push_back(hostRecord);
}

// Clear all host records.
void ClearHostRecords()
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.clientRecords_.clear();
}

// --- Scenario A: non-null token basic chain ---
// Covers: MessageEvent token check pass, PARAM_MESSAGE_KEY missing, GetFormRecord fail
void ScenarioA(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    int64_t formId = BASE_FORM_ID_A + 1;

    // A1: MessageEvent without PARAM_MESSAGE_KEY -> invalid-param branch (line 76)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        adapter.MessageEvent(formId, want, callerToken);
    }

    // A2: MessageEvent with PARAM_MESSAGE_KEY but no seeded record -> NOT_EXIST_ID (line 84)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetParam(Constants::PARAM_MESSAGE_KEY, GenerateSafeString(fdp, MAX_LENGTH));
        adapter.MessageEvent(formId, want, callerToken);
    }
}

// --- Scenario B: pre-seeded form record, no host record ---
// Covers: GetFormRecord success, GetMatchedHostClient fail
void ScenarioB(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    int64_t formId = BASE_FORM_ID_B + 1;

    FormRecord record = GenerateFormRecord(fdp);
    record.formId = formId;
    SeedFormRecord(formId, record);

    // B1: GetFormRecord succeeds, but clientRecords_ is empty -> GetMatchedHostClient fail (line 91)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetParam(Constants::PARAM_MESSAGE_KEY, GenerateSafeString(fdp, MAX_LENGTH));
        adapter.MessageEvent(formId, want, callerToken);
    }

    ClearFormRecord(formId);
}

// --- Scenario C: pre-seeded host record ---
// Covers: FormHostRecord::Contains fail, FormProviderMgr::MessageEvent deep path
void ScenarioC(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    int64_t formId = BASE_FORM_ID_C + 1;
    int64_t otherFormId = BASE_FORM_ID_C + 2;

    FormRecord record = GenerateFormRecord(fdp);
    record.formId = formId;
    SeedFormRecord(formId, record);

    // C1: Host record exists but does NOT contain formId -> Contains fail (line 96)
    {
        FormHostRecord hostRecord;
        hostRecord.SetFormHostClient(callerToken);
        hostRecord.SetCallerUid(fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID));
        hostRecord.SetHostBundleName(GenerateSafeString(fdp, MAX_LENGTH));
        hostRecord.AddForm(otherFormId);
        SeedHostRecord(hostRecord);

        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetParam(Constants::PARAM_MESSAGE_KEY, GenerateSafeString(fdp, MAX_LENGTH));
        adapter.MessageEvent(formId, want, callerToken);

        ClearHostRecords();
    }

    // C2: Host record contains formId -> reaches FormProviderMgr::MessageEvent (line 99)
    {
        FormHostRecord hostRecord;
        hostRecord.SetFormHostClient(callerToken);
        hostRecord.SetCallerUid(fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID));
        hostRecord.SetHostBundleName(GenerateSafeString(fdp, MAX_LENGTH));
        hostRecord.AddForm(formId);
        SeedHostRecord(hostRecord);

        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetParam(Constants::PARAM_MESSAGE_KEY, GenerateSafeString(fdp, MAX_LENGTH));
        adapter.MessageEvent(formId, want, callerToken);

        ClearHostRecords();
    }

    ClearFormRecord(formId);
}

// --- Scenario D: RouterEvent huge formId ---
// Covers: string SetParam branch, GetFormRecord fail, IsBundleMgrValid fail
void ScenarioD(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();

    // D1: Huge formId without seeded record -> string SetParam + GetFormRecord fail (lines 130-141)
    {
        int64_t hugeFormId = MAX_NUMBER_OF_JS + fdp->ConsumeIntegralInRange<int64_t>(1, MAX_FORM_ID);
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetBundle(GenerateSafeString(fdp, MAX_LENGTH));
        adapter.RouterEvent(hugeFormId, want, callerToken);
    }

    // D2: Huge formId with seeded record -> IsBundleMgrValid fail (line 147)
    {
        int64_t hugeFormId = MAX_NUMBER_OF_JS + BASE_FORM_ID_D + 1;
        FormRecord record = GenerateFormRecord(fdp);
        record.formId = hugeFormId;
        SeedFormRecord(hugeFormId, record);

        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetBundle(record.bundleName);
        adapter.RouterEvent(hugeFormId, want, callerToken);

        ClearFormRecord(hugeFormId);
    }
}

// --- Scenario E: BackgroundEvent pre-seeded record ---
// Covers: GetFormRecord success + IsBundleMgrValid fail
void ScenarioE(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    int64_t formId = BASE_FORM_ID_E + 1;

    FormRecord record = GenerateFormRecord(fdp);
    record.formId = formId;
    SeedFormRecord(formId, record);

    // E1: BackgroundEvent with seeded record -> IsBundleMgrValid fail (line 231)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        want.SetBundle(record.bundleName);
        adapter.BackgroundEvent(formId, want, callerToken);
    }

    ClearFormRecord(formId);
}

// --- Scenario F: SetFreeInstallFlag + OpenByOpenType ---
// Covers: FLAG_INSTALL_ON_DEMAND branches, all CardActionParamOpenType branches
void ScenarioF(FuzzedDataProvider *fdp)
{
    auto &adapter = FormEventAdapter::GetInstance();
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    int64_t formId = BASE_FORM_ID_F + 1;

    // F1: SetFreeInstallFlag with FLAG_INSTALL_ON_DEMAND + isSystemApp=true
    // -> SetParam(PARAM_FREE_INSTALL_CALLING_UID) branch (line 285)
    {
        FormRecord record;
        record.formId = formId;
        record.isSystemApp = true;
        record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        Want want;
        want.SetFlags(Want::FLAG_INSTALL_ON_DEMAND);
        adapter.SetFreeInstallFlag(record, want);
    }

    // F2: SetFreeInstallFlag with FLAG_INSTALL_ON_DEMAND + isSystemApp=false
    // -> RemoveFlags branch (line 288)
    {
        FormRecord record;
        record.formId = formId;
        record.isSystemApp = false;
        record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
        Want want;
        want.SetFlags(Want::FLAG_INSTALL_ON_DEMAND);
        adapter.SetFreeInstallFlag(record, want);
    }

    // F3: SetFreeInstallFlag without FLAG_INSTALL_ON_DEMAND -> early return (line 281)
    {
        FormRecord record;
        record.formId = formId;
        record.isSystemApp = true;
        Want want;
        want.SetFlags(0);
        adapter.SetFreeInstallFlag(record, want);
    }

    // Seed a form record for OpenByOpenType scenarios
    FormRecord seedRecord = GenerateFormRecord(fdp);
    seedRecord.formId = formId;
    seedRecord.isSystemApp = true;
    SeedFormRecord(formId, seedRecord);

    // F4: OpenByOpenType with isSystemApp=false -> permission deny (line 297)
    {
        FormRecord nonSysRecord = seedRecord;
        nonSysRecord.isSystemApp = false;
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        int32_t openResult = 0;
        adapter.OpenByOpenType(
            static_cast<int32_t>(Constants::CardActionParamOpenType::START_ABILITY),
            nonSysRecord, callerToken, want, openResult);
    }

    // F5: OpenByOpenType OPEN_APP_LINKING (isSystemApp=true)
    // -> GetCallerBundleName fail path (line 304-307)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        int32_t openResult = 0;
        adapter.OpenByOpenType(
            static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_APP_LINKING),
            seedRecord, callerToken, want, openResult);
    }

    // F6: OpenByOpenType OPEN_ATOMIC_SERVICE (isSystemApp=true)
    // -> OpenAtomicService fail path (line 324-327)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        int32_t openResult = 0;
        adapter.OpenByOpenType(
            static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_ATOMIC_SERVICE),
            seedRecord, callerToken, want, openResult);
    }

    // F7: OpenByOpenType START_ABILITY (isSystemApp=true) -> return false (line 335)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        int32_t openResult = 0;
        adapter.OpenByOpenType(
            static_cast<int32_t>(Constants::CardActionParamOpenType::START_ABILITY),
            seedRecord, callerToken, want, openResult);
    }

    // F8: OpenByOpenType with invalid openType (isSystemApp=true) -> return false (line 338)
    {
        Want want;
        want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
        int32_t openResult = 0;
        adapter.OpenByOpenType(INVALID_OPEN_TYPE, seedRecord, callerToken, want, openResult);
    }

    ClearFormRecord(formId);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int32_t scenario = fdp->ConsumeIntegralInRange<int32_t>(0, NUM_SCENARIOS - 1);
    switch (scenario) {
        case 0:
            ScenarioA(fdp);
            break;
        case 1:
            ScenarioB(fdp);
            break;
        case 2:
            ScenarioC(fdp);
            break;
        case 3:
            ScenarioD(fdp);
            break;
        case 4:
            ScenarioE(fdp);
            break;
        case 5:
            ScenarioF(fdp);
            break;
        default:
            break;
    }

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
