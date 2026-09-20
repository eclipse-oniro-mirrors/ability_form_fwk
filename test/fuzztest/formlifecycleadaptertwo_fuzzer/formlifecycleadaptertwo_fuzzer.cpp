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

#include <cctype>
#include "formlifecycleadaptertwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "ffrt.h"

#include "rdb_helper.h"

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

#define private public
#define protected public
#include "form_mgr/form_lifecycle_adapter.h"
#include "data_center/form_data_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/database/form_db_info.h"
#undef private
#undef protected

#include "form_constants.h"
#include "data_center/form_record/form_record.h"
#include "form_host/form_host_record.h"
#include "form_js_info.h"
#include "form_supply_stub.h"
#include "want.h"
#include "want_params.h"

// Interpose RdbHelper::GetRdbStore so no real rdb store is opened. Opening the
// store spawns async rdb threads that outlive the fuzz process and race with
// rdb's static SqlLog teardown at exit (heap-use-after-free).
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

// Non-null IRemoteObject stub for callerToken. Overrides the 7 pure virtual
// methods from IFormSupply so that iface_cast / IPC dispatch do not crash.
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

// --- Constants ---
constexpr int32_t MAX_LENGTH = 128;
constexpr int32_t NUM_SCENARIOS = 6;

// Distinct formId bases per scenario to isolate singleton state.
constexpr int64_t SCENARIO_A_BASE = 100000;
constexpr int64_t SCENARIO_B_BASE = 200000;
constexpr int64_t SCENARIO_C_BASE = 300000;
constexpr int64_t SCENARIO_D_BASE = 400000;
constexpr int64_t SCENARIO_E_BASE = 500000;

constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 10000;
constexpr const char* TEST_BUNDLE_A = "com.test.scenario.a";
constexpr const char* TEST_BUNDLE_C = "com.test.scenario.c";
constexpr const char* TEST_MODULE = "testModule";
constexpr const char* TEST_ABILITY = "testAbility";
constexpr const char* TEST_FORM_NAME = "testForm";

// --- Helpers ---
static std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safe;
    for (char c : result) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' ||
            c == '-' || c == '.' || c == '/' || c == ':') {
            safe += c;
        } else {
            safe += '_';
        }
    }
    return safe.empty() ? "default" : safe;
}

static Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH),
                        GenerateSafeString(fdp, MAX_LENGTH));
    want.SetAction(GenerateSafeString(fdp, MAX_LENGTH));
    return want;
}

static FormRecord MakeBaseRecord(int64_t formId, const std::string &bundleName)
{
    FormRecord r;
    r.formId = formId;
    r.bundleName = bundleName;
    r.moduleName = TEST_MODULE;
    r.abilityName = TEST_ABILITY;
    r.formName = TEST_FORM_NAME;
    r.userId = TEST_USER_ID;
    r.providerUserId = TEST_USER_ID;
    r.formUserUids = {TEST_CALLING_UID, TEST_CALLING_UID + 1};
    r.isDynamic = true;
    r.uiSyntax = FormType::ETS;
    r.formTempFlag = false;
    r.isSystemApp = false;
    r.isExistRecycleTask = false;
    r.enableForm = true;
    r.lockForm = false;
    return r;
}

static FormDBInfo MakeDBInfo(int64_t formId, const std::string &bundleName)
{
    FormDBInfo db;
    db.formId = formId;
    db.userId = TEST_USER_ID;
    db.providerUserId = TEST_USER_ID;
    db.formName = TEST_FORM_NAME;
    db.bundleName = bundleName;
    db.moduleName = TEST_MODULE;
    db.abilityName = TEST_ABILITY;
    db.formUserUids = {TEST_CALLING_UID, TEST_CALLING_UID + 1};
    return db;
}

// ===================================================================
// Scenario A: non-null token + pre-seeded state
// Covers: DeleteForm/ReleaseForm/CastTempForm past callerToken defense
//   -> GetMatchedHostClient success -> GetFormRecord success
//   -> HandleDeleteForm -> GetDBRecord success (FormDbCache seed)
//   -> deeper error branches (AMS/DB ops fail in fuzz env)
// ===================================================================
static void ScenarioA(FuzzedDataProvider *fdp)
{
    constexpr int64_t DEL_ID = SCENARIO_A_BASE + 1;
    constexpr int64_t REL_ID = SCENARIO_A_BASE + 2;
    constexpr int64_t CAST_ID = SCENARIO_A_BASE + 3;

    auto &adapter = FormLifecycleAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();
    auto &dbCache = FormDbCache::GetInstance();

    // Build non-null callerToken
    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    if (callerToken == nullptr) {
        return;
    }

    // --- Seed formRecords_ for DeleteForm and ReleaseForm ---
    FormRecord delRecord = MakeBaseRecord(DEL_ID, TEST_BUNDLE_A);
    dataMgr.formRecords_[DEL_ID] = delRecord;

    FormRecord relRecord = MakeBaseRecord(REL_ID, TEST_BUNDLE_A);
    dataMgr.formRecords_[REL_ID] = relRecord;

    // --- Seed formRecords_ + tempForms_ for CastTempForm ---
    FormRecord castRecord = MakeBaseRecord(CAST_ID, TEST_BUNDLE_A);
    castRecord.formTempFlag = true;
    dataMgr.formRecords_[CAST_ID] = castRecord;
    dataMgr.tempForms_.push_back(CAST_ID);

    // --- Seed clientRecords_ with matching token ---
    FormHostRecord hostRecord;
    hostRecord.SetFormHostClient(callerToken);
    hostRecord.AddForm(DEL_ID);
    hostRecord.AddForm(REL_ID);
    hostRecord.AddForm(CAST_ID);
    hostRecord.SetCallerUid(TEST_CALLING_UID);
    hostRecord.SetHostBundleName(TEST_BUNDLE_A);
    dataMgr.clientRecords_.push_back(hostRecord);

    // --- Seed FormDbCache::formDBInfos_ for DeleteForm/ReleaseForm ---
    dbCache.formDBInfos_.push_back(MakeDBInfo(DEL_ID, TEST_BUNDLE_A));
    dbCache.formDBInfos_.push_back(MakeDBInfo(REL_ID, TEST_BUNDLE_A));

    // Call 1: DeleteForm -> DeleteCommonForm -> HandleDeleteForm
    //   L699 pass (non-null token, formId>0)
    //   L723 -> DeleteCommonForm L583 -> HandleDeleteForm
    //   L413 GetDBRecord success (FormDbCache seed)
    //   L418 GetFormRecord success (formRecords_ seed)
    //   L429 isSelfDbFormId likely fails (uid mismatch) -> error branch
    adapter.DeleteForm(DEL_ID, callerToken);

    // Call 2: ReleaseForm with delCache=true -> HandleReleaseForm path
    //   L732 pass -> L740 ExistTempForm false -> L749 GetDBRecord success
    //   L759 isSelfDbFormId check -> L764 delCache true -> HandleReleaseForm
    //   L507 ExistFormRecord success -> L514 GetMatchedHostClient success
    adapter.ReleaseForm(REL_ID, callerToken, true);

    // Call 3: ReleaseForm with delCache=false -> skip HandleReleaseForm
    //   L764 delCache false -> L772 DeleteHostRecord
    adapter.ReleaseForm(REL_ID + 10, callerToken, false);

    // Call 4: CastTempForm -> deep branches
    //   L793 pass -> L799 ExistFormRecord+ExistTempForm both true
    //   L806 GetMatchedHostClient success (clientRecords_ seed)
    //   L807 isSelfId true (hostRecord contains CAST_ID)
    //   L815 CheckEnoughForm -> L822 GetFormRecord success
    //   L827 HandleCastTempForm -> ConnectServiceAbility fails -> error
    adapter.CastTempForm(CAST_ID, callerToken);
}

// ===================================================================
// Scenario B: extended Want params (AddForm path)
// Covers: token pass (L617), CheckAddFormTaskTimeoutOrFailed (L624),
//   CheckFormCountLimit temp branch (L107 -> L112) and non-temp branch
//   (L114 -> L115), InsertFormId for formId>0 (L636), GetFormConfigInfo
//   error branch (L643). AllotForm and below (L686) are not reached:
//   GetFormConfigInfo needs BMS, unavailable in the fuzz environment.
// ===================================================================
static void ScenarioB(FuzzedDataProvider *fdp)
{
    constexpr int64_t FORM_ID_NEW = 0;
    constexpr int64_t FORM_ID_EXISTING = SCENARIO_B_BASE + 1;

    auto &adapter = FormLifecycleAdapter::GetInstance();

    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    if (callerToken == nullptr) {
        return;
    }

    // Call 1: PARAM_FORM_TEMPORARY_KEY=true, formId=0
    //   -> CheckFormCountLimit L107 temp branch -> L112 CheckTempEnoughForm
    {
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_NEW, want, callerToken, formInfo);
    }

    // Call 2: IS_ADD_FORM_BY_HOST=true, formId=0
    //   -> CheckFormCountLimit L114 non-temp -> L115 CheckEnoughForm
    //   (the flag itself is only read inside AllotForm, BMS-gated)
    {
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::IS_ADD_FORM_BY_HOST, true);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_NEW, want, callerToken, formInfo);
    }

    // Call 3: KEY_DIRECT_CALL_INAPP=true, formId=0
    //   -> same AddForm prefix; flag is only read inside AllotForm (BMS-gated)
    {
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::KEY_DIRECT_CALL_INAPP, true);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_NEW, want, callerToken, formInfo);
    }

    // Call 4: PARAM_FORM_MIGRATE_FORM_KEY=true, formId>0
    //   -> L636 InsertFormId -> L643 GetFormConfigInfo BMS fail
    //   (migrate flag is only read inside AllotForm, BMS-gated)
    {
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::PARAM_FORM_MIGRATE_FORM_KEY, true);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_EXISTING, want, callerToken, formInfo);
    }

    // Call 5: formId>0 without migrate flag
    //   -> L636 InsertFormId -> L643 GetFormConfigInfo BMS fail
    {
        Want want = GenerateWant(fdp);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_EXISTING, want, callerToken, formInfo);
    }

    // Call 6: formId=0 without temp flag
    //   -> CheckFormCountLimit L114 non-temp -> L115 CheckEnoughForm
    //   -> L643 GetFormConfigInfo BMS fail
    {
        Want want = GenerateWant(fdp);
        FormJsInfo formInfo;
        adapter.AddForm(FORM_ID_NEW, want, callerToken, formInfo);
    }
}

// ===================================================================
// Scenario C: EnableForms/ProtectLockForms/SwitchLockForms loop body
// Covers: GetFormRecord(bundleName) success -> loop body entry
//   -> SetFormEnable/SetFormLock/UpdateDBRecord branches
// ===================================================================
static void ScenarioC(FuzzedDataProvider *fdp)
{
    constexpr int64_t FORM_ID_1 = SCENARIO_C_BASE + 1;
    constexpr int64_t FORM_ID_2 = SCENARIO_C_BASE + 2;

    auto &adapter = FormLifecycleAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();

    // Seed records with matching bundleName and providerUserId.
    // EnableForms uses GetFormRecord(bundleName, formInfos) - no userId filter.
    // ProtectLockForms/SwitchLockForms use GetFormRecord(bundleName, formInfos, userId).
    FormRecord r1 = MakeBaseRecord(FORM_ID_1, TEST_BUNDLE_C);
    r1.enableForm = false; // so enable=true enters the update branch
    r1.lockForm = false;
    dataMgr.formRecords_[FORM_ID_1] = r1;

    FormRecord r2 = MakeBaseRecord(FORM_ID_2, TEST_BUNDLE_C);
    r2.enableForm = true; // so enable=false enters the update branch
    r2.lockForm = true;
    dataMgr.formRecords_[FORM_ID_2] = r2;

    // Call 1: EnableForms with enable=true
    //   L1015 GetFormRecord(bundleName) success (seeded records match)
    //   L1021 loop body entry
    //   L1027 r1: enableForm(false)!=enable(true) && providerUserId==userId -> process
    //   L1027 r2: enableForm(true)==enable(true) -> erase+continue (skip branch)
    adapter.EnableForms(TEST_BUNDLE_C, TEST_USER_ID, true);

    // Call 2: ProtectLockForms with protect=true
    //   L1057 GetFormRecord(bundleName, formInfos, userId) success
    //   L1078 loop body entry
    //   L1081 IsExemptLock check -> L1085-1090 update branches
    adapter.ProtectLockForms(TEST_BUNDLE_C, TEST_USER_ID, true);

    // Call 3: SwitchLockForms with lock=true
    //   L1257 GetFormRecord(bundleName, formInfos, userId) success
    //   L1263 loop body entry
    //   L1270 r1: lockForm(false)!=lock(true) -> process
    //   L1283 unconditional ProtectLockForms call
    adapter.SwitchLockForms(TEST_BUNDLE_C, TEST_USER_ID, true);
}

// ===================================================================
// Scenario D: RecoverForms branches
// Covers: formId<=0 continue, !isDynamic continue,
//   isExistRecycleTask branch, FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT
// ===================================================================
static void ScenarioD(FuzzedDataProvider *fdp)
{
    constexpr int64_t STATIC_ID = SCENARIO_D_BASE + 1;
    constexpr int64_t DYNAMIC_RECYCLE_ID = SCENARIO_D_BASE + 2;
    constexpr int64_t CLICK_ID = SCENARIO_D_BASE + 3;

    auto &adapter = FormLifecycleAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();

    // Record (a): isDynamic=false -> L1134 continue branch
    FormRecord staticRec = MakeBaseRecord(STATIC_ID, TEST_BUNDLE_A);
    staticRec.isDynamic = false;
    dataMgr.formRecords_[STATIC_ID] = staticRec;

    // Record (b): isDynamic=true + isExistRecycleTask=true
    //   -> L1134 passes, L1140 isExistRecycleTask true -> enters recovery
    //   -> L1145 formUserUids check (may fail due to uid mismatch) -> continue
    FormRecord dynamicRec = MakeBaseRecord(DYNAMIC_RECYCLE_ID, TEST_BUNDLE_A);
    dynamicRec.isDynamic = true;
    dynamicRec.isExistRecycleTask = true;
    dataMgr.formRecords_[DYNAMIC_RECYCLE_ID] = dynamicRec;

    // Record (c): for click-event recover variant
    FormRecord clickRec = MakeBaseRecord(CLICK_ID, TEST_BUNDLE_A);
    clickRec.isDynamic = true;
    clickRec.isExistRecycleTask = false;
    dataMgr.formRecords_[CLICK_ID] = clickRec;

    // Call 1: RecoverForms without click-event flag
    //   formIds: {-1, STATIC_ID, DYNAMIC_RECYCLE_ID}
    //   -1 -> L1122 formId<=0 continue
    //   STATIC_ID -> L1134 !isDynamic continue
    //   DYNAMIC_RECYCLE_ID -> L1140 isExistRecycleTask true -> passes
    //     -> L1145 formUserUids check -> likely continue (uid mismatch)
    {
        std::vector<int64_t> formIds = {-1, STATIC_ID, DYNAMIC_RECYCLE_ID};
        Want want = GenerateWant(fdp);
        adapter.RecoverForms(formIds, want);
    }

    // Call 2: RecoverForms with FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT=true
    //   CLICK_ID: L1140 needHandleCachedClick=true -> passes the recycle check
    //   -> L1145 formUserUids check -> likely continue
    {
        std::vector<int64_t> formIds = {CLICK_ID};
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, true);
        adapter.RecoverForms(formIds, want);
    }
}

// ===================================================================
// Scenario E: RecycleForms / GetRecycleFormIdIfValid non-uid branches
// Covers: formTempFlag invalid, !isDynamic invalid, uiSyntax!=ETS invalid
// Skipped: uid-dependent branches (IPCSkeleton::GetCallingUid runtime value)
// ===================================================================
static void ScenarioE(FuzzedDataProvider *fdp)
{
    constexpr int64_t TEMP_ID = SCENARIO_E_BASE + 1;
    constexpr int64_t STATIC_ID = SCENARIO_E_BASE + 2;
    constexpr int64_t JS_SYNTAX_ID = SCENARIO_E_BASE + 3;

    auto &adapter = FormLifecycleAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();

    // Record (a): formTempFlag=true -> L1177 INVALID_FORM_ID
    FormRecord tempRec = MakeBaseRecord(TEMP_ID, TEST_BUNDLE_A);
    tempRec.formTempFlag = true;
    tempRec.isDynamic = true;
    tempRec.uiSyntax = FormType::ETS;
    dataMgr.formRecords_[TEMP_ID] = tempRec;

    // Record (b): isDynamic=false -> L1181 INVALID_FORM_ID
    FormRecord staticRec = MakeBaseRecord(STATIC_ID, TEST_BUNDLE_A);
    staticRec.formTempFlag = false;
    staticRec.isDynamic = false;
    staticRec.uiSyntax = FormType::ETS;
    dataMgr.formRecords_[STATIC_ID] = staticRec;

    // Record (c): uiSyntax=JS (not ETS) -> L1185 INVALID_FORM_ID
    FormRecord jsRec = MakeBaseRecord(JS_SYNTAX_ID, TEST_BUNDLE_A);
    jsRec.formTempFlag = false;
    jsRec.isDynamic = true;
    jsRec.uiSyntax = FormType::JS;
    dataMgr.formRecords_[JS_SYNTAX_ID] = jsRec;

    // Call: RecycleForms with all 3 seeded formIds
    //   Each hits a different INVALID_FORM_ID branch in GetRecycleFormIdIfValid.
    //   validFormIds empty -> L1221 ERR_FORM_INVALID_PARAM
    //   isCheckCallingUid=false to exercise the non-strict path (L1198)
    {
        std::vector<int64_t> formIds = {TEMP_ID, STATIC_ID, JS_SYNTAX_ID};
        Want want = GenerateWant(fdp);
        adapter.RecycleForms(formIds, want, false);
    }

    // Call 2: RecycleForms with isCheckCallingUid=true
    //   Exercises L1193 isCheckCallingUid branch
    {
        std::vector<int64_t> formIds = {TEMP_ID, STATIC_ID, JS_SYNTAX_ID};
        Want want = GenerateWant(fdp);
        adapter.RecycleForms(formIds, want, true);
    }
}

// ===================================================================
// Scenario F: negative formId pass
// Covers: formId<=0 early-return in DeleteForm/ReleaseForm/CastTempForm
//   and formId<=0 continue in RecoverForms/RecycleForms
// ===================================================================
static void ScenarioF(FuzzedDataProvider *fdp)
{
    auto &adapter = FormLifecycleAdapter::GetInstance();

    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    if (callerToken == nullptr) {
        return;
    }

    // Generate negative formId
    int64_t negFormId = -(static_cast<int64_t>(1 + (fdp->ConsumeIntegralInRange<int32_t>(0, 9999))));

    // Call 1: DeleteForm with negative formId -> L699 formId<=0 early return
    adapter.DeleteForm(negFormId, callerToken);

    // Call 2: ReleaseForm with negative formId -> L732 formId<=0 early return
    adapter.ReleaseForm(negFormId, callerToken, true);

    // Call 3: CastTempForm with negative formId -> L793 formId<=0 early return
    adapter.CastTempForm(negFormId, callerToken);

    // Call 4: RecoverForms with negative formId -> L1122 formId<=0 continue
    {
        std::vector<int64_t> formIds = {negFormId, negFormId - 1};
        Want want = GenerateWant(fdp);
        adapter.RecoverForms(formIds, want);
    }

    // Call 5: RecycleForms with negative formId
    //   -> GetRecycleFormIdIfValid L1168 formId<=0 -> INVALID_FORM_ID
    {
        std::vector<int64_t> formIds = {negFormId};
        Want want = GenerateWant(fdp);
        adapter.RecycleForms(formIds, want, false);
    }

    // Call 6: AddForm with negative formId -> L617 formId<0 early return
    {
        Want want = GenerateWant(fdp);
        FormJsInfo formInfo;
        adapter.AddForm(negFormId, want, callerToken, formInfo);
    }

    // Call 7: DeleteInvalidForms with non-null token but empty/invalid ids
    {
        std::vector<int64_t> formIds = {negFormId, 0};
        int32_t numDeleted = 0;
        adapter.DeleteInvalidForms(formIds, callerToken, numDeleted);
    }
}

// --- Entry ---
static bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t scenario = fdp->ConsumeIntegral<uint8_t>();
    switch (scenario % NUM_SCENARIOS) {
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
