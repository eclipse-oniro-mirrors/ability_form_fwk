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

#include "formdbcacheannex_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_db_cache.h"
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
    FormDbCache formDbCache;
    int64_t formId = static_cast<int64_t>(GetU32Data(data));
    FormRecord record;
    formDbCache.GetDBRecord(formId, record);
    FormDBInfo records;
    formDbCache.GetDBRecord(formId, records);
    formDbCache.UpdateDBRecord(formId, record);
    int uid = static_cast<int>(GetU32Data(data));
    std::set<int64_t> formNums;
    formNums.insert(formId);
    std::string bundleName(data, size);
    std::string abilityName(data, size);
    FormIdKey formIdKey(bundleName, abilityName);
    std::map<FormIdKey, std::set<int64_t>> noHostFormDBList;
    noHostFormDBList.emplace(formIdKey, formNums);
    std::map<int64_t, bool> foundFormsMap;
    bool flag = *data % ENABLE;
    foundFormsMap.emplace(formId, flag);
    formDbCache.GetNoHostDBForms(uid, noHostFormDBList, foundFormsMap);
    std::string moduleName(data, size);
    formDbCache.GetMatchCount(bundleName, moduleName);
    int32_t userId = static_cast<int32_t>(GetU32Data(data));
    formDbCache.DeleteDBFormsByUserId(userId);
    int32_t callingUid = static_cast<int32_t>(GetU32Data(data));
    std::set<int64_t> matchedFormIds;
    matchedFormIds.insert(formId);
    formDbCache.GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostFormDBList, foundFormsMap);
    formDbCache.BatchDeleteNoHostDBForms(callingUid, noHostFormDBList, foundFormsMap);
    formDbCache.DeleteInvalidDBForms(userId, callingUid, matchedFormIds, foundFormsMap);
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

