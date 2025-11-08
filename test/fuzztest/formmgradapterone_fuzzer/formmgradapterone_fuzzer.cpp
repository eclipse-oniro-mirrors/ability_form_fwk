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

#include "formmgradapterone_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_mgr/form_mgr_adapter.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    FormRecord record;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    WantParams wantParams;
    FormJsInfo formInfo;
    formMgrAdapter.AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo);
    formMgrAdapter.AllotFormByInfo(info, callerToken, wantParams, formInfo);
    formMgrAdapter.AddNewFormRecord(info, formId, callerToken, wantParams, formInfo);
    formMgrAdapter.AddFormTimer(record);
    std::string providerKey(data, size);
    std::vector<int64_t> formIdsByProvider;
    formIdsByProvider.emplace_back(formId);
    int32_t formVisibleType = static_cast<int32_t>(GetU32Data(data));
    formMgrAdapter.HandleEventNotify(providerKey, formIdsByProvider, formVisibleType);
    formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams);
    AAFwk::Want want;
    BundleInfo bundleInfo;
    std::string packageName(data, size);
    formMgrAdapter.GetBundleInfo(want, bundleInfo, packageName);
    FormInfo formInfos;
    formMgrAdapter.GetFormInfo(want, formInfos);
    formMgrAdapter.GetFormItemInfo(want, bundleInfo, formInfos, info);
    int dimensionId = static_cast<int>(GetU32Data(data));
    formMgrAdapter.IsDimensionValid(formInfos, dimensionId);
    formMgrAdapter.CreateFormItemInfo(bundleInfo, formInfos, info);
    Want wants;
    formMgrAdapter.CheckPublishForm(wants);
    formMgrAdapter.QueryPublishFormToHost(wants);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

