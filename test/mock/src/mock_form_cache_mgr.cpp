/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "data_center/form_cache_mgr.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {

FormCacheMgr::FormCacheMgr() {}
FormCacheMgr::~FormCacheMgr() {}

void FormCacheMgr::Start() {}

bool FormCacheMgr::AddData(int64_t formId, const FormProviderData &formProviderData)
{
    return true;
}

bool FormCacheMgr::DeleteData(int64_t formId)
{
    return true;
}

bool FormCacheMgr::GetData(int64_t formId, std::string &data,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    return false;
}

bool FormCacheMgr::NeedAcquireProviderData(int64_t formId) const
{
    return false;
}

bool FormCacheMgr::IsDirtyDataCleaned() const
{
    return true;
}

void FormCacheMgr::SetIsDirtyDataCleaned() {}

bool FormCacheMgr::GetFormCacheIds(std::unordered_set<int64_t> &formIds)
{
    return false;
}

bool FormCacheMgr::DeleteDataCacheInDb(int64_t formId)
{
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
