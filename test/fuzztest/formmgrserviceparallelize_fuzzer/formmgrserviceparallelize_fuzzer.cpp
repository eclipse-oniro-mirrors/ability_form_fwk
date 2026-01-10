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

#include "formmgrserviceparallelize_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "form_mgr/form_mgr_service.h"
#undef private
#undef protected
#include "strategy/include/form_constants_fuzzer.h"
#include "strategy/include/form_parallelize_fuzz_util.h"
#include "strategy/include/form_parallelize_fuzz_base.h"
#include "strategy/include/form_host_parallelize_fuzz.h"
#include "strategy/include/form_provider_parallelize_fuzz.h"
#include "strategy/include/form_observer_parallelize_fuzz.h"
#include "strategy/include/form_other_parallelize_fuzz.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::FuzzerConstants;

namespace OHOS {
auto g_formMgrService = std::make_shared<FormMgrService>();
auto g_formParallelizeUtil = std::make_shared<FormParallelizeFuzzUtil>();
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (SetSelfTokenID(TOKEN_ID | (1uLL << OFFSET)) < 0) {
        return -1;
    }

    if (g_formMgrService == nullptr || g_formParallelizeUtil == nullptr) {
        return -1;
    }

    g_formMgrService->OnStart();
    return 0;
}

extern "C" int FuzzIFormMgrService(FuzzedDataProvider &provider)
{
    if (g_formMgrService == nullptr || g_formParallelizeUtil == nullptr) {
        return 0;
    }

    std::unordered_map<IpcType, std::unique_ptr<FormParallelizeFuzzBase>> strategies;
    strategies[IpcType::TYPE_HOST] = std::make_unique<FormHostParallelizeFuzz>(g_formMgrService,
        g_formParallelizeUtil);
    strategies[IpcType::TYPE_PROVIDER] = std::make_unique<FormProviderParallelizeFuzz>(g_formMgrService,
        g_formParallelizeUtil);
    strategies[IpcType::TYPE_OBSERVER] = std::make_unique<FormObserverParallelizeFuzz>(g_formMgrService,
        g_formParallelizeUtil);
    strategies[IpcType::TYPE_OTHER] = std::make_unique<FormOtherParallelizeFuzz>(g_formMgrService,
        g_formParallelizeUtil);

    IpcType code = provider.PickValueInArray<IpcType>({
        IpcType::TYPE_HOST, IpcType::TYPE_PROVIDER, IpcType::TYPE_OBSERVER, IpcType::TYPE_OTHER
    });

    auto iter = strategies.find(code);
    if (iter != strategies.end()) {
        iter->second->Execute(provider);
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    FuzzIFormMgrService(fdp);
    return 0;
}