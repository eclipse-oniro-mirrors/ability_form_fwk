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

#include "formsyseventreceiver_fuzzer.h"

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
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    EventFwk::CommonEventSubscribeInfo subscriberInfo;
    FormSysEventReceiver formSysEventReceiver(subscriberInfo);
    EventFwk::CommonEventData eventData;
    formSysEventReceiver.OnReceiveEvent(eventData);
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    FormRecord formRecord;
    FormInfo formInfo;
    std::vector<FormInfo> targetForms;
    targetForms.emplace_back(formInfo);
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int userId = fdp->ConsumeIntegral<int>();
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    int32_t userIds = fdp->ConsumeIntegral<int32_t>();
    FormEventUtil::HandleProviderRemoved(bundleName, userIds);
    BundlePackInfo bundlePackInfo;
    BundleInfo bundleInfo;
    bool needReload = fdp->ConsumeBool();
    FormEventUtil::ProviderFormUpdated(formId, formRecord, bundlePackInfo, bundleInfo);
    FormEventUtil::HandleBundleFormInfoChanged(bundleName, userIds, needReload);
    FormEventUtil::HandleUpdateFormCloud(bundleName);
    FormEventUtil::HandleBundleFormInfoRemoved(bundleName, userIds);
    FormEventUtil::HandleBundleDataCleared(bundleName, userIds);
    int uid = fdp->ConsumeIntegral<int>();
    FormEventUtil::HandleFormHostDataCleared(uid);
    AAFwk::Want want;
    formSysEventReceiver.HandlePackageDataCleared(bundleName, userId);
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
