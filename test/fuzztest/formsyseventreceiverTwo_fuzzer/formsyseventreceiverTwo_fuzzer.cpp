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

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "common/event/system_event/form_sys_event_receiver.h"
#undef private
#undef protected
#include "securec.h"
#include "ffrt.h"

extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
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

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr size_t MAX_LENGTH = 5;
constexpr int32_t MIN_USER_ID = -1;
constexpr int32_t MAX_USER_ID = 1000;
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
    int64_t batchFormId = fdp->ConsumeIntegral<int64_t>();
    int batchUid = fdp->ConsumeIntegral<int>();
    formNums.insert(batchFormId);
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    noHostFormDbMap.emplace(formIdKey, formNums);
    FormEventUtil::BatchDeleteNoHostDBForms(batchUid, noHostFormDbMap, removedFormsMap);
    FormEventUtil::BatchDeleteNoHostTempForms(batchUid, noHostFormDbMap, removedFormsMap);
    int64_t reCreateFormId = fdp->ConsumeIntegral<int64_t>();
    FormEventUtil::ReCreateForm(reCreateFormId);
    FormTimerCfg cfg;
    FormRecord formRecord;
    int64_t timerFormId = fdp->ConsumeIntegral<int64_t>();
    formRecord.formId = timerFormId;
    formRecord.isEnableUpdate = fdp->ConsumeBool();
    cfg.enableUpdate = fdp->ConsumeBool();
    FormEventUtil::HandleTimerUpdate(timerFormId, formRecord, cfg);
    formSysEventReceiver.HandleUserIdRemoved(fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID));
    formSysEventReceiver.HandleBundleScanFinished();
    FormInfo formInfo;
    formInfo.bundleName = bundleName;
    BundleInfo bundleInfo;
    std::vector<FormInfo> targetForms;
    targetForms.emplace_back(formInfo);
    int64_t providerFormId = fdp->ConsumeIntegral<int64_t>();
    return FormEventUtil::ProviderFormUpdated(providerFormId, formRecord, targetForms, bundleInfo);
}
}

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