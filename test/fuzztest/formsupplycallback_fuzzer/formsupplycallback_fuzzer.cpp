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

#include "formsupplycallback_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "data_center/form_info/form_info_storage.h"
#define private public
#define protected public
#include "common/util/form_dump_mgr.h"
#include "common/util/form_serial_queue.h"
#include "form_provider/form_supply_callback.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t INDEX_MAX = 2;
void FormSerialQueueTest(FuzzedDataProvider *fdp)
{
    std::string queueName = fdp->ConsumeRandomLengthString();
    FormSerialQueue formSerialQueue(queueName);
    uint64_t ms = fdp->ConsumeIntegral<uint64_t>();
    uint32_t msg = fdp->ConsumeIntegral<uint32_t>();
    auto testTask = []() {};
    int64_t num1 = fdp->ConsumeIntegral<int64_t>();
    int64_t num2 = fdp->ConsumeIntegral<int64_t>();
    int64_t num3 = fdp->ConsumeIntegral<int64_t>();
    std::string str1 = fdp->ConsumeRandomLengthString();
    std::pair<int64_t, int64_t> eventMsg = std::make_pair(num1, num2);
    std::pair<int64_t, std::string> eventMsgStr = std::make_pair(num3, str1);
    formSerialQueue.ScheduleTask(ms, testTask);
    formSerialQueue.ScheduleDelayTask(eventMsg, msg, testTask);
    formSerialQueue.CancelDelayTask(eventMsg);
    formSerialQueue.ScheduleDelayTask(eventMsgStr, msg, testTask);
    formSerialQueue.CancelDelayTask(eventMsgStr);
}

void FormDumpMgrTestPartOne(FuzzedDataProvider *fdp)
{
    FormDumpMgr formDumpMgr;
    std::vector<Constants::FormLocation> locations = {Constants::FormLocation::OTHER,
        Constants::FormLocation::DESKTOP, Constants::FormLocation::FORM_CENTER,
        Constants::FormLocation::FORM_MANAGER, Constants::FormLocation::NEGATIVE_SCREEN,
        Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN,
        Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN,
        Constants::FormLocation::SCREEN_LOCK, Constants::FormLocation::AI_SUGGESTION};
    Constants::FormLocation formLocation = locations.at(fdp->ConsumeIntegralInRange<size_t>(0, locations.size() - 1));
    std::string infosResult = fdp->ConsumeRandomLengthString();
    formDumpMgr.AppendFormLocation(formLocation, infosResult);
    std::vector<BundleType> formBundleTypes = {BundleType::APP, BundleType::ATOMIC_SERVICE, BundleType::SHARED};
    BundleType formBundleType = formBundleTypes.at(fdp->ConsumeIntegralInRange<size_t>(0, formBundleTypes.size() - 1));
    std::string formInfo = fdp->ConsumeRandomLengthString();
    formDumpMgr.AppendBundleType(formBundleType, formInfo);
    std::string key = fdp->ConsumeRandomLengthString();
    std::string value = fdp->ConsumeRandomLengthString();
    std::unordered_map<std::string, std::string> liveFormStatusMap = {{key, value}};
    std::string formId = fdp->ConsumeRandomLengthString();
    formDumpMgr.AppendLiveFormStatus(formId, liveFormStatusMap, formInfo);
}

void FormDumpMgrTest(FuzzedDataProvider *fdp)
{
    FormDumpMgr formDumpMgr;
    FormDBInfo formDBInfo;
    std::vector<FormDBInfo> storageInfos;
    storageInfos.emplace_back(formDBInfo);
    std::string formInfoes = fdp->ConsumeRandomLengthString();
    formDumpMgr.DumpStorageFormInfos(storageInfos, formInfoes);
    FormRecord formRecord;
    std::vector<FormRecord> formRecordInfos;
    formRecordInfos.emplace_back(formRecord);
    formDumpMgr.DumpFormInfos(formRecordInfos, formInfoes);
    FormHostRecord formHostRecord;
    std::string formInfo = fdp->ConsumeRandomLengthString();
    formDumpMgr.DumpFormHostInfo(formHostRecord, formInfo);
    formDumpMgr.DumpFormInfo(formRecord, formInfo);
    formDumpMgr.DumpTemporaryFormInfos(formRecordInfos, formInfo);
    std::vector<FormInfo> bundleFormInfos;
    formDumpMgr.DumpStaticBundleFormInfos(bundleFormInfos, formInfo);
    int32_t tokenId = fdp->ConsumeIntegral<int32_t>();
    std::string bundleName = fdp->ConsumeRandomLengthString();
    int32_t instIndex = fdp->ConsumeIntegral<int32_t>();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    formDumpMgr.DumpHasFormVisible(tokenId, bundleName, userId, instIndex, formInfo);
    std::vector<std::string> subscribedKeys;
    int32_t index = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    for (int32_t i = 0; i < index; i++) {
        subscribedKeys.push_back(fdp->ConsumeRandomLengthString());
    }
    int64_t count = fdp->ConsumeIntegral<int64_t>();
    std::string formHostBundleName = fdp->ConsumeRandomLengthString();
    RunningFormInfo runningFormInfo;
    runningFormInfo.hostBundleName = formHostBundleName;
    std::vector<FormVisibilityType> formVisiblitys = {FormVisibilityType::UNKNOWN,
        FormVisibilityType::VISIBLE, FormVisibilityType::INVISIBLE};
    std::vector<FormUsageState> usageStates = {FormUsageState::USED, FormUsageState::UNUSED};
    runningFormInfo.formVisiblity = formVisiblitys.at(fdp->ConsumeIntegralInRange<size_t>(0,
        formVisiblitys.size() - 1));
    runningFormInfo.formUsageState = usageStates.at(fdp->ConsumeIntegralInRange<size_t>(0,
        usageStates.size() - 1));
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo};
    formDumpMgr.DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    std::string infosResult = fdp->ConsumeRandomLengthString();
    formDumpMgr.AppendRunningFormInfos(formHostBundleName, runningFormInfos, infosResult);
    formDumpMgr.DumpRunningFormInfos(runningFormInfos, infosResult);
    OHOS::FormDumpMgrTestPartOne(fdp);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormSupplyCallback formSupplyCallback;
    formSupplyCallback.GetInstance();
    FormProviderInfo formProviderInfo;
    Want want;
    formSupplyCallback.OnAcquire(formProviderInfo, want);
    formSupplyCallback.OnEventHandle(want);
    FormState state = FormState::UNKNOWN;
    std::string provider = fdp->ConsumeRandomLengthString();
    Want wantArg;
    formSupplyCallback.OnAcquireStateResult(state, provider, wantArg, want);
    sptr<FormAbilityConnection> connection = nullptr;
    formSupplyCallback.AddConnection(connection);
    int32_t connectId = fdp->ConsumeIntegral<int32_t>();
    formSupplyCallback.RemoveConnection(connectId);
    formSupplyCallback.CanDisconnect(connection);
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string remoteDeviceId = fdp->ConsumeRandomLengthString();
    AAFwk::WantParams wantParams;
    int64_t requestCode = fdp->ConsumeIntegral<int64_t>();
    bool result = fdp->ConsumeBool();
    formSupplyCallback.OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);
    sptr<IRemoteObject> hostToken = nullptr;
    formSupplyCallback.RemoveConnection(formId, hostToken);
    formSupplyCallback.HandleHostDied(hostToken);
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    FormInfo info;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(info);
    AAFwk::FormInfoStorage formInfoStorage(userId, formInfos);
    formInfoStorage.GetAllFormsInfo(userId, formInfos);
    std::string moduleName = fdp->ConsumeRandomLengthString();
    formInfoStorage.GetFormsInfoByModule(userId, moduleName, formInfos);
    OHOS::FormDumpMgrTest(fdp);
    OHOS::FormSerialQueueTest(fdp);
    return formSupplyCallback.IsRemoveConnection(formId, hostToken);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}