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
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr long long TOKEN_ID = 718336240uLL;
constexpr long long OFFSET = 32;
class OHOS::AppExecFwk::FormMgrService* p_formMgrService = new OHOS::AppExecFwk::FormMgrService();

enum IpcCode : std::int16_t {
    ADD_FORM = 3001,
    DELETE_FORM = 3003,
};

sptr<IRemoteObject> GetMockRemoteObject()
{
    return nullptr;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (SetSelfTokenID(TOKEN_ID | (1uLL << OHOS::OFFSET)) < 0) {
        return -1;
    }
    OHOS::p_formMgrService->OnStart();
    return 0;
}

extern "C" int FuzzIFormMgrService(FuzzedDataProvider &provider)
{
    if (p_formMgrService == nullptr) {
        return 0;
    }

    static const int ipcCodes[] = {
        IpcCode::ADD_FORM, IpcCode::DELETE_FORM
    };
    int code = provider.PickValueInArray(ipcCodes);

    switch (code) {
        case IpcCode::ADD_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            Want want;
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            FormJsInfo formInfo;
            OHOS::p_formMgrService->AddForm(formId, want, callerToken, formInfo);
            break;
        }
        case IpcCode::DELETE_FORM: {
            int64_t formId = provider.ConsumeIntegral<int64_t>();
            sptr<IRemoteObject> callerToken = OHOS::GetMockRemoteObject();
            OHOS::p_formMgrService->DeleteForm(formId, callerToken);
            break;
        }
        default: {
            break;
        }
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    FuzzIFormMgrService(fdp);
    return 0;
}