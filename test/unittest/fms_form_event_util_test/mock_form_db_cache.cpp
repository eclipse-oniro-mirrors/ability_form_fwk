/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "hilog_wrapper.h"

namespace {
    bool g_mockGetMatchCountRet = true;
    bool g_mockGetNoHostDBFormsOne = true;
    bool g_mockGetNoHostDBFormsTwo = true;
}

void MockGetMatchCount(bool mockRet)
{
    g_mockGetMatchCountRet = mockRet;
}

void MockGetNoHostDBFormsOne(bool mockRet)
{
    g_mockGetNoHostDBFormsOne = mockRet;
}

void MockGetNoHostDBFormsTwo(bool mockRet)
{
    g_mockGetNoHostDBFormsTwo = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDbCache::FormDbCache()
{
    HILOG_INFO("FormDbCache is created");
}

FormDbCache::~FormDbCache()
{
    HILOG_INFO("FormDbCache is destroyed");
}

ErrCode FormDbCache::DeleteFormInfoByBundleName(const std::string &bundleName, const int32_t userId,
    std::vector<FormDBInfo> &removedDBForms)
{
    FormDBInfo formDBInfo;
    formDBInfo.bundleName = "aa";
    removedDBForms.emplace_back(formDBInfo);
    return ERR_OK;
}

int FormDbCache::GetMatchCount(const std::string &bundleName, const std::string &moduleName)
{
    if (true == g_mockGetMatchCountRet) {
        return 1;
    }
    return 0;
}

ErrCode FormDbCache::GetNoHostDBForms(const int uid, std::map<FormIdKey,
    std::set<int64_t>> &noHostFormDBList, std::map<int64_t, bool> &foundFormsMap)
{
    int64_t formId = 1;
    std::string bundleName = "com.form.start";
    std::string abilityName = "bbbbbb";
    if (false == g_mockGetNoHostDBFormsOne) {
        FormIdKey formIdKey(bundleName, abilityName);
        std::set<int64_t> formIdsSet;
        formIdsSet.emplace(formId);
        noHostFormDBList.emplace(formIdKey, formIdsSet);
    }
    if (false == g_mockGetNoHostDBFormsTwo) {
        foundFormsMap.emplace(formId, false);
    }                    
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
