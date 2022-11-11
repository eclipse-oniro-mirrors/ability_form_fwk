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

#include "forminfostoragemgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_info_storage_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    KvStoreDeathRecipientCallbackFormInfoStorage kvStoreDeathRecipientCallbackFormInfoStorage;
    FormInfoStorageMgr formInfoStorageMgr;
    std::string aa(data, size);
    std::string bb(data, size);
    std::pair<std::string, std::string> loadForm = std::make_pair(aa, bb);
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    formInfoStorages.emplace_back(loadForm);
    formInfoStorageMgr.LoadFormInfos(formInfoStorages);
    std::string bundleName(data, size);
    formInfoStorageMgr.RemoveBundleFormInfos(bundleName);
    std::string formInfoStorags(data, size);
    formInfoStorageMgr.UpdateBundleFormInfos(bundleName, formInfoStorags);
    formInfoStorageMgr.GetKvStore();
    formInfoStorageMgr.CheckKvStore();
    formInfoStorageMgr.RegisterKvStoreDeathListener();
    formInfoStorageMgr.ResetKvStore();
    std::vector<InnerFormInfo> innerFormInfos;
    InnerFormInfo innerFormInfo;
    innerFormInfos.emplace_back(innerFormInfo);
    formInfoStorageMgr.LoadFormData(innerFormInfos);
    std::string formId(data, size);
    formInfoStorageMgr.GetStorageFormInfoById(formId, innerFormInfo);
    formInfoStorageMgr.SaveStorageFormInfo(innerFormInfo);
    formInfoStorageMgr.ModifyStorageFormInfo(innerFormInfo);
    formInfoStorageMgr.DeleteStorageFormInfo(formId);
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

