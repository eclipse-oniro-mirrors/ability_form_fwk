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

#include "formcallermgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_caller_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    FormCallerMgr formCallerMgr;
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    formCallerMgr.RemoveFormHostCaller(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    formCallerMgr.RemoveFormHostCaller(callerToken);
    wptr<IRemoteObject> remote = nullptr;
    formCallerMgr.OnHostCallBackDied(remote);
    sptr<IRemoteObject> remotes = nullptr;
    formCallerMgr.HandleHostCallBackDiedTask(remotes);
    std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers;
    std::shared_ptr<FormProviderCaller> formProviderCaller = nullptr;
    formProviderCallers.emplace_back(formProviderCaller);
    formCallerMgr.GetFormProviderCaller(formId, formProviderCallers);
    formCallerMgr.RemoveFormProviderCaller(formId, callerToken);
    formCallerMgr.RemoveFormProviderCaller(callerToken);
    formCallerMgr.OnProviderCallBackDied(remote);
    formCallerMgr.HandleProviderCallBackDiedTask(remotes);
    return formCallerMgr.GetFormHostCaller(formId) == nullptr;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}

