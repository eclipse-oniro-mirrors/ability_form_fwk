/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>

#include "data_center/form_info/form_info_storage.h"
#define private public
#define protected public
#include "common/util/form_serial_queue.h"
#include "form_provider/form_supply_callback.h"
#undef private
#undef protected
#include "securec.h"
#include "rdb_helper.h"
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

namespace AppExecFwk {
// Override GetInstance to return a process-lifetime sptr instead of a
// function-local static that gets destroyed on fuzzer exit. The stack-local
// construction in the fuzzer creates an IRemoteStub whose OnFirstStrongRef
// spawns an IPC work thread that outlives the stub destruction at function
// return, causing heap-use-after-free. Holding it in a process-lifetime sptr
// keeps the stub alive for the entire fuzzer run.
sptr<FormSupplyCallback> FormSupplyCallback::GetInstance()
{
    static sptr<FormSupplyCallback> instance = sptr<FormSupplyCallback>::MakeSptr();
    return instance;
}
} // namespace AppExecFwk
} // namespace OHOS

using namespace OHOS::AppExecFwk;

namespace OHOS {

void FormSerialQueueTest(FuzzedDataProvider *fdp)
{
    std::string queueName = fdp->ConsumeRandomLengthString();
    FormSerialQueue formSerialQueue(queueName);
    uint64_t ms = fdp->ConsumeIntegral<uint64_t>();
    uint32_t msg = fdp->ConsumeIntegral<uint32_t>();
    auto testTask = []() {};
    int64_t num1 = fdp->ConsumeIntegral<int64_t>();
    int64_t num2 = fdp->ConsumeIntegral<int64_t>();
    std::pair<int64_t, int64_t> eventMsg = std::make_pair(num1, num2);
    formSerialQueue.ScheduleTask(ms, testTask);
    formSerialQueue.ScheduleDelayTask(eventMsg, msg, testTask);
    formSerialQueue.CancelDelayTask(eventMsg);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    auto formSupplyCallback = FormSupplyCallback::GetInstance();
    if (formSupplyCallback != nullptr) {
        FormProviderInfo formProviderInfo;
        Want want;
        formSupplyCallback->OnAcquire(formProviderInfo, want);
        formSupplyCallback->OnEventHandle(want);
        FormState state = FormState::UNKNOWN;
        std::string provider = fdp->ConsumeRandomLengthString();
        Want wantArg;
        formSupplyCallback->OnAcquireStateResult(state, provider, wantArg, want);
        sptr<FormAbilityConnection> connection = nullptr;
        formSupplyCallback->AddConnection(connection);
        int32_t connectId = fdp->ConsumeIntegral<int32_t>();
        formSupplyCallback->RemoveConnection(connectId);
        formSupplyCallback->ShouldDisconnectImmediately(connection);
        int64_t formId = fdp->ConsumeIntegral<int64_t>();
        std::string remoteDeviceId = fdp->ConsumeRandomLengthString();
        AAFwk::WantParams wantParams;
        int64_t requestCode = fdp->ConsumeIntegral<int64_t>();
        bool result = fdp->ConsumeBool();
        formSupplyCallback->OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);
        sptr<IRemoteObject> hostToken = nullptr;
        formSupplyCallback->RemoveConnection(formId, hostToken);
        formSupplyCallback->HandleHostDied(hostToken);
        formSupplyCallback->IsRemoveConnection(formId, hostToken);
    }
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    FormInfo info;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(info);
    AAFwk::FormInfoStorage formInfoStorage(userId, formInfos);
    formInfoStorage.GetAllFormsInfo(userId, formInfos);
    std::string moduleName = fdp->ConsumeRandomLengthString();
    formInfoStorage.GetFormsInfoByModule(userId, moduleName, formInfos);
    OHOS::FormSerialQueueTest(fdp);
    return true;
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