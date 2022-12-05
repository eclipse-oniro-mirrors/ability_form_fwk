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

#include "form_db_cache.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockGetDBRecordRet = true;
    bool g_mockDeleteFormInfoRet = true;
    bool g_mockGetMatchCountRet = true;
}

void MockGetDBRecord(bool mockRet)
{
    g_mockGetDBRecordRet = mockRet;
}

void MockDeleteFormInfo(bool mockRet)
{
    g_mockDeleteFormInfoRet = mockRet;
}

void MockGetMatchCount(bool mockRet)
{
    g_mockGetMatchCountRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDbCache::FormDbCache()
{}

FormDbCache::~FormDbCache()
{}

ErrCode FormDbCache::GetDBRecord(const int64_t formId, FormRecord &record) const
{
    if (true == g_mockGetDBRecordRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}

ErrCode FormDbCache::DeleteFormInfo(int64_t formId)
{
    if (true == g_mockDeleteFormInfoRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int FormDbCache::GetMatchCount(const std::string &bundleName, const std::string &moduleName)
{
    int32_t matchCount = 0;
    if (true == g_mockGetMatchCountRet) {
        return matchCount;
    }
    return matchCount + 1;
}
} // namespace AppExecFwk
} // namespace OHOS
