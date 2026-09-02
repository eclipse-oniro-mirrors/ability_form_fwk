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

#include "formhostrefreshimpl_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#include "rdb_helper.h"

#define private public
#define protected public
#include "form_refresh/refresh_impl/form_host_refresh_impl.h"
#include "form_refresh/strategy/refresh_config.h"
#undef private
#undef protected

// Interpose RdbHelper::GetRdbStore so no real rdb store is opened. Opening the
// store spawns an async backup thread that outlives the fuzz process and races
// with rdb's static SqlLog teardown at exit (heap-use-after-free).
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

// The fuzz target links the real form service stack, whose FormDataMgr registers a
// memory-watermark parameter watcher. Its IPC-thread callback can submit ffrt tasks
// after the global scheduler is torn down at process exit (heap-use-after-free). The
// watcher path is not reachable from fuzz input, so stub the registration as no-op.
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;

RefreshData GenerateFuzzedRefreshData(FuzzedDataProvider *fdp)
{
    RefreshData data;
    if (fdp == nullptr) {
        return data;
    }
    data.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    data.nextTime = fdp->ConsumeIntegral<int64_t>();
    data.callingUid = fdp->ConsumeIntegral<int32_t>();
    data.record.formId = data.formId;
    data.record.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    data.record.isSystemApp = fdp->ConsumeBool();
    data.record.isEnableUpdate = fdp->ConsumeBool();
    data.record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    data.formTimer.formId = data.formId;
    data.formTimer.refreshTime = fdp->ConsumeIntegral<int64_t>();
    data.formTimer.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, MAX_NUM);
    data.callerToken = nullptr;
    return data;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormHostRefreshImpl formHostRefresh;
    RefreshData data = GenerateFuzzedRefreshData(fdp);

    // Test public method
    formHostRefresh.RefreshFormRequest(data);

    // Test protected method DoControlCheck (override — FormHostRefreshImpl overrides DoControlCheck instead of DoRefresh)
    formHostRefresh.DoControlCheck(data);

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
