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

#include "formrefresh_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "form_constants.h"

#define private public
#include "form_refresh/refresh_impl/form_refresh_after_uncontrol_impl.h"
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/refresh_impl/form_app_upgrade_refresh_impl.h"
#undef private
#include "message_parcel.h"
#include "securec.h"
#include "form_refresh/check_mgr/active_user_checker.h"
#include "form_refresh/check_mgr/add_finish_checker.h"
#include "form_refresh/check_mgr/calling_bundle_checker.h"
#include "form_refresh/check_mgr/calling_user_checker.h"
#include "form_refresh/check_mgr/self_form_checker.h"
#include "form_refresh/check_mgr/system_app_checker.h"
#include "form_refresh/refresh_impl/form_data_refresh_impl.h"
#include "form_refresh/refresh_impl/form_force_refresh_impl.h"
#include "form_refresh/refresh_impl/form_host_refresh_impl.h"
#include "form_refresh/refresh_impl/form_net_conn_refresh_impl.h"
#include "form_refresh/refresh_impl/form_next_time_refresh_impl.h"
#include "form_refresh/refresh_impl/form_provider_refresh_impl.h"
#include "status_mgr_center/form_status.h"
#include "feature/param_update/param_control.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t MAX_STRING_SIZE = 20;

/**
 * @brief Generate fuzzed FormRecord with comprehensive field coverage
 */
FormRecord GenerateFuzzedFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    if (fdp == nullptr) {
        return formRecord;
    }
    record.formId = fdp->ConsumeIntegral<int64_t>();
    record.bundleName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.moduleName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.abilityName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.formName = fdp->ConsumeRandomLengthString(MAX_STRING_SIZE);
    record.specification = fdp->ConsumeIntegral<int32_t>();
    record.isEnableUpdate = fdp->ConsumeBool();
    record.isVisible = fdp->ConsumeBool();
    record.enableForm = fdp->ConsumeBool();
    record.isDataProxy = fdp->ConsumeBool();
    record.formVisibleNotifyState = fdp->ConsumeIntegral<int>();
    record.isTimerRefresh = fdp->ConsumeBool();
    record.isHostRefresh = fdp->ConsumeBool();
    record.isRefreshDuringDisableForm = fdp->ConsumeBool();
    record.isUpdateDuringDisableForm = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.userId = fdp->ConsumeIntegral<int32_t>();
    record.providerUserId = fdp->ConsumeIntegral<int32_t>();
    record.versionCode = fdp->ConsumeIntegral<uint32_t>();
    record.isDynamic = fdp->ConsumeBool();
    record.renderingMode = static_cast<Constants::RenderingMode>(fdp->ConsumeIntegral<int32_t>());
    return record;
}

void RefreshControlMgrTest(FuzzedDataProvider *fdp)
{
    FormRecord record;
    if (fdp == nullptr) {
        return;
    }
    record.formVisibleNotifyState = fdp->ConsumeIntegral<int>();
    record.enableForm = fdp->ConsumeBool();
    record.isVisible = fdp->ConsumeBool();
    record.isDataProxy = fdp->ConsumeBool();
    bool isVisibleToFresh = fdp->ConsumeBool();
    RefreshControlMgr::GetInstance().IsSystemOverload();
    RefreshControlMgr::GetInstance().IsFormInvisible(record);
    RefreshControlMgr::GetInstance().IsScreenOff(record);
    RefreshControlMgr::GetInstance().IsHealthyControl(record);
    RefreshControlMgr::GetInstance().IsNeedToFresh(record, isVisibleToFresh);
    RefreshData data;
    data.record = record;
    FormAppUpgradeRefreshImpl::GetInstance().RefreshFormRequest(data);
}

void RefreshCacheMgrTest(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    int64_t taskFormId = fdp->ConsumeIntegral<int64_t>();
    int32_t taskUserId = fdp->ConsumeIntegral<int32_t>();
    int32_t refreshType = fdp->ConsumeIntegral<int32_t>();

    // Test FormTimer task queue operations
    FormTimer task;
    task.formId = taskFormId;
    task.userId = taskUserId;
    RefreshCacheMgr::GetInstance().AddToOverloadTaskQueue(task);
    RefreshCacheMgr::GetInstance().ConsumeOverloadTaskQueue();

    // Test healthy control flag operations
    bool isAskForProviderData = fdp->ConsumeBool();
    RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(formId, isAskForProviderData);

    // Test invisible flag operations
    RefreshCacheMgr::GetInstance().AddFlagByInvisible(formId, refreshType);
    RefreshCacheMgr::GetInstance().ConsumeInvisibleFlag(formId, userId);

    // Test screen off flag operations
    Want want;
    FormRecord record = GenerateFuzzedFormRecord(fdp);
    RefreshCacheMgr::GetInstance().AddFlagByScreenOff(formId, want, record);
    RefreshCacheMgr::GetInstance().ConsumeScreenOffFlag();

    // Test render task operations
    std::function<void()> func = []() { return; };
    RefreshCacheMgr::GetInstance().AddRenderTask(formId, func);
    RefreshCacheMgr::GetInstance().ConsumeRenderTask(formId);
    RefreshCacheMgr::GetInstance().DelRenderTask(formId);

    // Test ConsumeHealthyControlFlag with fuzzed FormRecord
    std::vector<FormRecord> formRecords;
    size_t vectorSize = fdp->ConsumeIntegralInRange<size_t>(1, 3);
    for (size_t i = 0; i < vectorSize; ++i) {
        FormRecord rec = GenerateFuzzedFormRecord(fdp);
        rec.formId = fdp->ConsumeIntegral<int64_t>();
        formRecords.push_back(rec);
    }
    if (!formRecords.empty()) {
        auto it = formRecords.begin();
        RefreshCacheMgr::GetInstance().ConsumeHealthyControlFlag(it, userId);
    }

    // Test CosumeRefreshByDueControl
    RefreshCacheMgr::GetInstance().CosumeRefreshByDueControl(formRecords);

    // Test ConsumeAddUnfinishFlag
    int64_t addFormId = fdp->ConsumeIntegral<int64_t>();
    RefreshCacheMgr::GetInstance().ConsumeAddUnfinishFlag(addFormId, userId);

    // Test private CreateWant method
    if (!formRecords.empty()) {
        auto it = formRecords.begin();
        RefreshCacheMgr::GetInstance().CreateWant(it, userId);
    }
}

void FormStatusTest(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    int64_t num = fdp->ConsumeIntegralInRange(0, 1000);
    FormFsmStatus formStatus;
    FormStatus::GetInstance().SetFormStatus(num, FormFsmStatus::RECYCLING);
    FormStatus::GetInstance().HasFormStatus(formId);
    FormStatus::GetInstance().IsFormProcessRecycle(formId);
    FormStatus::GetInstance().GetFormStatus(formId);
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::INIT);
    FormStatus::GetInstance().DeleteFormStatus(formId);
}

void FormRefreshTest(FuzzedDataProvider *fdp)
{
    bool isTrue = (fdp->ConsumeIntegralInRange(0, 1000)) % 2;
    bool isFalse = (fdp->ConsumeIntegralInRange(0, 1000)) % 2;
    int32_t callingUid = fdp->ConsumeIntegralInRange(0, 1000);
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    RefreshData data;
    int64_t nextTime = fdp->ConsumeIntegralInRange(0, 1000);
    FormTimer formTimer;
    sptr<IRemoteObject> callerToken;
    FormProviderData providerData;
    FormRecord record;
    Want want;
    data.nextTime = nextTime;
    data.callingUid = callingUid;
    record.isSystemApp = isTrue;
    record.formId = formId;
    record.isDataProxy = isTrue;
    data.record = record;
    data.formTimer = formTimer;
    data.callerToken = callerToken;
    data.want = want;
    data.providerData = providerData;
    FormDataRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormForceRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormHostRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormNextTimeRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data);
    FormRefreshAfterUncontrolImpl::GetInstance().DetectControlPoint(data, isTrue, isFalse);
    FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data);
    FormTimerRefreshImpl::GetInstance().DealRefresh(data);
    FormTimerRefreshImpl::GetInstance().DetectControlPoint(data, isTrue, isFalse);
    FormTimerRefreshImpl::GetInstance().BuildTimerWant(formTimer, want);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    bool isTrue = (fdp->ConsumeIntegralInRange(0, 1000)) % 2;
    bool isFalse = (fdp->ConsumeIntegralInRange(0, 1000)) % 2;
    int32_t num = fdp->ConsumeIntegralInRange(0, 1000);
    int32_t num32 = fdp->ConsumeIntegralInRange(0, 1000);
    int32_t callingUid = fdp->ConsumeIntegralInRange(0, 1000);
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    CheckValidFactor reqFactor;
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, num32);
    FormRecord record;
    record.providerUserId = num;
    reqFactor.formId = formId;
    reqFactor.callingUid = callingUid;
    reqFactor.want = want;
    reqFactor.record = record;
    ActiveUserChecker::GetInstance().CheckValid(reqFactor);
    AddFinishChecker::GetInstance().CheckValid(reqFactor);
    CallingBundleChecker::GetInstance().CheckValid(reqFactor);
    CallingUserChecker::GetInstance().CheckValid(reqFactor);
    SelfFormChecker::GetInstance().CheckValid(reqFactor);
    SystemAppChecker::GetInstance().CheckValid(reqFactor);
    OHOS::FormRefreshTest(fdp);
    OHOS::FormStatusTest(fdp);
    OHOS::RefreshCacheMgrTest(fdp);
    OHOS::RefreshControlMgrTest(fdp);
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
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    free(ch);
    ch = nullptr;
    return 0;
}
