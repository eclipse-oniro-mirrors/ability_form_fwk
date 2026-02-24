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

#include "formdatamgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_data_mgr.h"
#include "bms_mgr/form_bundle_event_callback.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormItemInfo formInfo;
    int callingUid = fdp->ConsumeIntegral<int>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    FormDataMgr::GetInstance().AllotFormRecord(formInfo, callingUid, userId);
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    FormDataMgr::GetInstance().DeleteFormRecord(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    FormDataMgr::GetInstance().AllotFormHostRecord(formInfo, callerToken, formId, callingUid);
    FormHostRecord record;
    FormDataMgr::GetInstance().CreateHostRecord(formInfo, callerToken, callingUid, record);
    FormDataMgr::GetInstance().CreateFormRecord(formInfo, callingUid, userId);
    FormRecord records;
    FormJsInfo formInfos;
    FormDataMgr::GetInstance().CreateFormJsInfo(formId, records, formInfos);
    FormDataMgr::GetInstance().CheckTempEnoughForm();
    int32_t currentUserId = fdp->ConsumeIntegral<int32_t>();
    FormDataMgr::GetInstance().CheckEnoughForm(callingUid, currentUserId);
    FormDataMgr::GetInstance().DeleteTempForm(formId);
    FormDataMgr::GetInstance().ExistTempForm(formId);
    FormBundleEventCallback formBundleEventCallback;
    EventFwk::CommonEventData eventData;
    formBundleEventCallback.OnReceiveEvent(eventData);
    Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    eventData.SetWant(want);
    formBundleEventCallback.OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    eventData.SetWant(want);
    formBundleEventCallback.OnReceiveEvent(eventData);

    want.SetAction(BMS_EVENT_ADDITIONAL_INFO_CHANGED);
    eventData.SetWant(want);
    formBundleEventCallback.OnReceiveEvent(eventData);

    std::string bundleName = fdp->ConsumeRandomLengthString();
    bool flag = fdp->ConsumeBool();
    formBundleEventCallback.HandleBundleChange(bundleName, userId, flag);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}