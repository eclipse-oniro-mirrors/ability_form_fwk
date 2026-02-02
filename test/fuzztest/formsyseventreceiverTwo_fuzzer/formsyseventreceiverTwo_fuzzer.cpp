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

#include "formsyseventreceiverTwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/event/system_event/form_sys_event_receiver.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t MAX_LENGTH = 5;
constexpr int32_t INVALID_USER = -1;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    EventFwk::CommonEventSubscribeInfo subscriberInfo;
    FormSysEventReceiver formSysEventReceiver(subscriberInfo);
    EventFwk::CommonEventData eventData;
    formSysEventReceiver.HandleUserSwitched(eventData);
    bool flag = fdp->ConsumeBool();
    std::map<int64_t, bool> removedFormsMap;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    int uid = fdp->ConsumeIntegral<int>();
    removedFormsMap.emplace(formId, flag);
    FormEventUtil::ClearFormDBRecordData(uid, removedFormsMap);
    FormEventUtil::ClearTempFormRecordData(uid, removedFormsMap);
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormIdKey formIdKey(bundleName, abilityName);
    std::set<int64_t> formNums;
    formNums.insert(formId);
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    noHostFormDbMap.emplace(formIdKey, formNums);
    FormEventUtil::BatchDeleteNoHostDBForms(uid, noHostFormDbMap, removedFormsMap);
    FormEventUtil::BatchDeleteNoHostTempForms(uid, noHostFormDbMap, removedFormsMap);
    FormEventUtil::ReCreateForm(formId);
    FormTimerCfg cfg;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isEnableUpdate = fdp->ConsumeBool();
    cfg.enableUpdate = fdp->ConsumeBool();
    FormEventUtil::HandleTimerUpdate(formId, formRecord, cfg);
    formSysEventReceiver.HandleUserIdRemoved(INVALID_USER);
    formSysEventReceiver.HandleBundleScanFinished();
    FormInfo formInfo;
    formInfo.bundleName = bundleName;
    BundleInfo bundleInfo;
    std::vector<FormInfo> targetForms;
    targetForms.emplace_back(formInfo);
    return FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}