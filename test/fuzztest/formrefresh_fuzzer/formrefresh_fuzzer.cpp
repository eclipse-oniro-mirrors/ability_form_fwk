/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "status_mgr_center/form_status.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
void FormStatusTest(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    FormFsmStatus formStatus;
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RENDERED);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RECYCLED);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RENDERING);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RECYCLING_DATA);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RECYCLING);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::RECOVERING);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::DELETING);
    FormStatus::GetInstance().SetFormStatus(fdp->ConsumeIntegralInRange(0, 1000), FormFsmStatus::UNPROCESSABLE);
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
    record.providerUserId = fdp->ConsumeIntegralInRange(0, 1000);
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

