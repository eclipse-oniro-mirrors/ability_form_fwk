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

#include "form_info_storage.h"
#define private public
#define protected public
#include "form_dump_mgr.h"
#include "form_supply_callback.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormSupplyCallback formSupplyCallback;
    formSupplyCallback.GetInstance();
    FormProviderInfo formProviderInfo;
    Want want;
    formSupplyCallback.OnAcquire(formProviderInfo, want);
    formSupplyCallback.OnEventHandle(want);
    FormState state = FormState::UNKNOWN;
    std::string provider(data, size);
    Want wantArg;
    formSupplyCallback.OnAcquireStateResult(state, provider, wantArg, want);
    sptr<FormAbilityConnection> connection = nullptr;
    formSupplyCallback.AddConnection(connection);
    int32_t connectId = static_cast<int32_t>(GetU32Data(data));
    formSupplyCallback.RemoveConnection(connectId);
    formSupplyCallback.CanDisconnect(connection);
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    std::string remoteDeviceId(data, size);
    AAFwk::WantParams wantParams;
    int64_t requestCode = static_cast<int64_t>(GetU32Data(data));
    bool result = *data % ENABLE;
    formSupplyCallback.OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);
    sptr<IRemoteObject> hostToken = nullptr;
    formSupplyCallback.RemoveConnection(formId, hostToken);
    formSupplyCallback.HandleHostDied(hostToken);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    FormInfo info;
    std::vector<FormInfo> formInfos;
    formInfos.emplace_back(info);
    AAFwk::FormInfoStorage formInfoStorage(userId, formInfos);
    formInfoStorage.GetAllFormsInfo(userId, formInfos);
    std::string moduleName(data, size);
    formInfoStorage.GetFormsInfoByModule(userId, moduleName, formInfos);
    FormDumpMgr formDumpMgr;
    FormDBInfo formDBInfo;
    std::vector<FormDBInfo> storageInfos;
    storageInfos.emplace_back(formDBInfo);
    std::string formInfoes(data, size);
    formDumpMgr.DumpStorageFormInfos(storageInfos, formInfoes);
    FormRecord formRecord;
    std::vector<FormRecord> formRecordInfos;
    formRecordInfos.emplace_back(formRecord);
    formDumpMgr.DumpFormInfos(formRecordInfos, formInfoes);
    FormHostRecord formHostRecord;
    std::string formInfo(data, size);
    formDumpMgr.DumpFormHostInfo(formHostRecord, formInfo);
    formDumpMgr.DumpFormInfo(formRecord, formInfo);
    return formSupplyCallback.IsRemoveConnection(formId, hostToken);
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

    /* Validate the length of size */
    if (size == 0 || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

