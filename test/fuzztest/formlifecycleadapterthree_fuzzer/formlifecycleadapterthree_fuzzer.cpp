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

#include "formlifecycleadapterthree_fuzzer.h"

#include <cctype>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
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

#define private public
#define protected public
#include "form_mgr/form_lifecycle_adapter.h"
#include "data_center/form_data_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/database/form_db_info.h"
#undef private
#undef protected

#include "configuration.h"
#include "form_constants.h"
#include "form_constants_util.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "form_js_info.h"
#include "form_supply_stub.h"
#include "running_form_info.h"
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
constexpr int32_t NUM_SCENARIOS = 4;

// Distinct formId bases per scenario to isolate singleton state.
constexpr int64_t SCENARIO_A_BASE = 600000;
constexpr int64_t SCENARIO_B_BASE = 700000;
constexpr int64_t SCENARIO_C_BASE = 800000;
constexpr int64_t SCENARIO_D_BASE = 900000;

constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 10000;
// Below TEST_USER_ID so GetFormRecordsByUserId returns empty (no seeded match).
constexpr int32_t UNSEEDED_USER_ID_MAX = 99;
constexpr const char* TEST_BUNDLE_A = "com.test.scenario.a";
constexpr const char* TEST_BUNDLE_D = "com.test.scenario.d";
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

static FormItemInfo GenerateFormItemInfo(FuzzedDataProvider *fdp, int64_t formId)
{
    FormItemInfo info;
    info.SetFormId(formId);
    info.SetProviderBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    info.SetModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    info.SetAbilityName(GenerateSafeString(fdp, MAX_LENGTH));
    info.SetFormName(GenerateSafeString(fdp, MAX_LENGTH));
    return info;
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
    r.isDynamic = true;
    r.uiSyntax = FormType::ETS;
    r.formTempFlag = false;
    r.isSystemApp = false;
    r.enableForm = true;
    r.lockForm = false;
    r.needRefresh = false;
    r.needAddForm = false;
    r.isLocationChange = false;
    r.isInited = true;
    return r;
}

static void ScenarioA(FuzzedDataProvider *fdp)
{
    auto &adapter = FormLifecycleAdapter::GetInstance();

    // Call 1: needRefresh=true -> needAcquire true -> AcquireProviderFormInfoAsync
    {
        FormItemInfo info = GenerateFormItemInfo(fdp, SCENARIO_A_BASE + 1);
        FormRecord record = MakeBaseRecord(SCENARIO_A_BASE + 1, TEST_BUNDLE_A);
        record.needRefresh = true;
        WantParams params;
        adapter.ProcessProviderAcquire(info, record, SCENARIO_A_BASE + 1, params);
    }

    // Call 2: needAddForm=true -> needAcquire true
    {
        FormItemInfo info = GenerateFormItemInfo(fdp, SCENARIO_A_BASE + 2);
        FormRecord record = MakeBaseRecord(SCENARIO_A_BASE + 2, TEST_BUNDLE_A);
        record.needAddForm = true;
        WantParams params;
        adapter.ProcessProviderAcquire(info, record, SCENARIO_A_BASE + 2, params);
    }

    // Call 3: needAcquire=false + isLocationChange=true -> ConnectAmsChangeLocation
    {
        FormItemInfo info = GenerateFormItemInfo(fdp, SCENARIO_A_BASE + 3);
        FormRecord record = MakeBaseRecord(SCENARIO_A_BASE + 3, TEST_BUNDLE_A);
        record.needRefresh = false;
        record.needAddForm = false;
        record.isLocationChange = true;
        WantParams params;
        adapter.ProcessProviderAcquire(info, record, SCENARIO_A_BASE + 3, params);
    }

    // Call 4: needAcquire=false + isLocationChange=false -> return ERR_OK
    {
        FormItemInfo info = GenerateFormItemInfo(fdp, SCENARIO_A_BASE + 4);
        FormRecord record = MakeBaseRecord(SCENARIO_A_BASE + 4, TEST_BUNDLE_A);
        record.needRefresh = false;
        record.needAddForm = false;
        record.isLocationChange = false;
        WantParams params;
        adapter.ProcessProviderAcquire(info, record, SCENARIO_A_BASE + 4, params);
    }

    // Call 5: inverse-color param -> needAcquire true (different sub-branch)
    {
        FormItemInfo info = GenerateFormItemInfo(fdp, SCENARIO_A_BASE + 5);
        FormRecord record = MakeBaseRecord(SCENARIO_A_BASE + 5, TEST_BUNDLE_A);
        record.needRefresh = true;
        Want want;
        want.SetParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY, true);
        WantParams params = want.GetParams();
        adapter.ProcessProviderAcquire(info, record, SCENARIO_A_BASE + 5, params);
    }
}

static void ScenarioB(FuzzedDataProvider *fdp)
{
    auto &adapter = FormLifecycleAdapter::GetInstance();

    constexpr int64_t ACTIVE_ID = SCENARIO_B_BASE + 1;
    constexpr int64_t INACTIVE_ID = SCENARIO_B_BASE + 2;
    constexpr int64_t PAUSE_ID = SCENARIO_B_BASE + 3;
    constexpr int64_t UNKNOWN_ID = SCENARIO_B_BASE + 4;
    constexpr int64_t ABSENT_ID = SCENARIO_B_BASE + 5;

    std::unordered_map<std::string, std::string> liveFormStatusMap = {
        { std::to_string(ACTIVE_ID), LiveFormState::ACTIVE },
        { std::to_string(INACTIVE_ID), LiveFormState::INACTIVE },
        { std::to_string(PAUSE_ID), LiveFormState::PAUSE },
        { std::to_string(UNKNOWN_ID), GenerateSafeString(fdp, MAX_LENGTH) },
    };

    // Each call exercises a different branch of the find/compare logic.
    adapter.IsLiveFormActive(ACTIVE_ID, liveFormStatusMap);
    adapter.IsLiveFormActive(INACTIVE_ID, liveFormStatusMap);
    adapter.IsLiveFormActive(PAUSE_ID, liveFormStatusMap);
    adapter.IsLiveFormActive(UNKNOWN_ID, liveFormStatusMap);
    adapter.IsLiveFormActive(ABSENT_ID, liveFormStatusMap);
}

static void ScenarioC(FuzzedDataProvider *fdp)
{
    auto &adapter = FormLifecycleAdapter::GetInstance();

    sptr<IRemoteObject> callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
    if (callerToken == nullptr) {
        return;
    }

    // Call 1: tempFormFlag=true -> L631 skip HandleFormAddObserver
    {
        int64_t formId = SCENARIO_C_BASE + 1;
        FormItemInfo info = GenerateFormItemInfo(fdp, formId);
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);
        FormJsInfo formJsInfo;
        adapter.HandleAddRequestPublishForm(formId, want, callerToken, formJsInfo, info);
    }

    // Call 2: tempFormFlag=false -> L633 HandleFormAddObserver branch
    {
        int64_t formId = SCENARIO_C_BASE + 2;
        FormItemInfo info = GenerateFormItemInfo(fdp, formId);
        Want want = GenerateWant(fdp);
        want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
        FormJsInfo formJsInfo;
        adapter.HandleAddRequestPublishForm(formId, want, callerToken, formJsInfo, info);
    }

    // Call 3: tempFormFlag absent (defaults false) -> HandleFormAddObserver branch
    {
        int64_t formId = SCENARIO_C_BASE + 3;
        FormItemInfo info = GenerateFormItemInfo(fdp, formId);
        Want want = GenerateWant(fdp);
        FormJsInfo formJsInfo;
        adapter.HandleAddRequestPublishForm(formId, want, callerToken, formJsInfo, info);
    }
}

static void ScenarioD(FuzzedDataProvider *fdp)
{
    constexpr int64_t FORM_ID_D1 = SCENARIO_D_BASE + 1;
    constexpr int64_t FORM_ID_D2 = SCENARIO_D_BASE + 2;
    constexpr int64_t FORM_ID_D3 = SCENARIO_D_BASE + 3;

    auto &adapter = FormLifecycleAdapter::GetInstance();
    auto &dataMgr = FormDataMgr::GetInstance();

    // Seed formRecords_ with records matching TEST_USER_ID so
    // GetFormRecordsByUserId returns them and the loop body is entered.
    FormRecord r1 = MakeBaseRecord(FORM_ID_D1, TEST_BUNDLE_D);
    dataMgr.formRecords_[FORM_ID_D1] = r1;

    FormRecord r2 = MakeBaseRecord(FORM_ID_D2, TEST_BUNDLE_D);
    // Distinct ability to exercise a different dedup key.
    r2.abilityName = "testAbilityD2";
    dataMgr.formRecords_[FORM_ID_D2] = r2;

    // FORM_ID_D3 is intentionally NOT seeded in formRecords_ so that
    // ConsumeColorModeCache hits the GetFormRecordById "not found -> continue"
    // branch (L1672-1674).

    Configuration configuration;
    // Call 1: BatchNotify with seeded records.
    //   GetFormsInfoByRecord likely fails (FormInfoMgr unseeded) -> continue.
    adapter.BatchNotifyFormsColorModeUpdate(TEST_USER_ID, configuration);

    // Call 2: BatchNotify with no records (unknown userId) -> empty loop.
    int32_t emptyUserId = fdp->ConsumeIntegralInRange<int32_t>(0, UNSEEDED_USER_ID_MAX);
    adapter.BatchNotifyFormsColorModeUpdate(emptyUserId, configuration);

    // Seed colorModeUpdateCache_ directly so ConsumeColorModeCache exercises
    // the cache-lookup + erase logic under the lock.
    {
        std::lock_guard<std::mutex> lock(adapter.colorModeCacheMutex_);
        std::string key1 = std::to_string(TEST_USER_ID) + "::" + TEST_BUNDLE_D + "::" + TEST_ABILITY;
        std::string key2 = std::to_string(TEST_USER_ID) + "::" + TEST_BUNDLE_D + "::testAbilityD2";
        adapter.colorModeUpdateCache_[key1] = configuration;
        adapter.colorModeUpdateCache_[key2] = configuration;
    }

    // Call 3: ConsumeColorModeCache with seeded cache + seeded records.
    //   FORM_ID_D1/D2 found in formRecords_ -> proceed to cache lookup.
    //   FORM_ID_D3 not found -> continue (skip).
    {
        std::vector<int64_t> formIds = { FORM_ID_D1, FORM_ID_D2, FORM_ID_D3 };
        adapter.ConsumeColorModeCache(formIds, TEST_USER_ID);
    }

    // Call 4: ConsumeColorModeCache with empty formIds -> early return (L1665-1667).
    adapter.ConsumeColorModeCache({}, TEST_USER_ID);

    // Call 5: ConsumeColorModeCache with empty cache -> early return.
    {
        std::lock_guard<std::mutex> lock(adapter.colorModeCacheMutex_);
        adapter.colorModeUpdateCache_.clear();
    }
    adapter.ConsumeColorModeCache({ FORM_ID_D1 }, TEST_USER_ID);

    // Remove seeded records to avoid polluting later iterations.
    dataMgr.formRecords_.erase(FORM_ID_D1);
    dataMgr.formRecords_.erase(FORM_ID_D2);
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
