/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "data_center/database/form_db_cache.h"

#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "ipc_skeleton.h"

namespace {
    bool g_mockGetDBRecordRet = true;
    bool g_mockGetDBRecordParam = false;
    bool g_mockDeleteFormInfoRet = true;
    bool g_mockGetMatchCountRet = true;
    bool g_mockUpdateDBRecordRet = true;
    bool g_mockGetAllFormInfo = false;
}

void MockGetDBRecord(bool mockRet)
{
    g_mockGetDBRecordRet = mockRet;
}

void MockGetDBRecordParam(bool mockRet)
{
    g_mockGetDBRecordParam = mockRet;
}

void MockDeleteFormInfo(bool mockRet)
{
    g_mockDeleteFormInfoRet = mockRet;
}

void MockGetMatchCount(bool mockRet)
{
    g_mockGetMatchCountRet = mockRet;
}

void MockUpdateDBRecord(bool mockRet)
{
    g_mockUpdateDBRecordRet = mockRet;
}

void MockGetAllFormInfo(bool mockRet)
{
    g_mockGetAllFormInfo = mockRet;
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
        if (g_mockGetDBRecordParam) {
            int32_t callingUid = IPCSkeleton::GetCallingUid();
            record.userId = FormUtil::GetCallerUserId(callingUid);
            record.formUserUids.push_back(callingUid);
            record.providerUserId = record.userId;
        }
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

ErrCode FormDbCache::UpdateDBRecord(const int64_t formId, const FormRecord &record) const
{
    if (true == g_mockUpdateDBRecordRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

void FormDbCache::GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos)
{
    if (g_mockGetAllFormInfo) {
        FormDBInfo info1 = {};
        info1.formId = 1;
        FormDBInfo info2 = {};
        info2.formId = 2;
        formDBInfos.push_back(info1);
        formDBInfos.push_back(info2);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
