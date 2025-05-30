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

#include "data_center/form_cache_mgr.h"

namespace {
    bool g_mockDeleteDataRet = true;
    bool g_mockIsExistRet = true;
    bool g_mockGetDataRet = true;
    bool g_mockAddDataRet = true;
}

void MockDeleteData(bool mockRet)
{
    g_mockDeleteDataRet = mockRet;
}

void MockIsExist(bool mockRet)
{
    g_mockIsExistRet = !mockRet;
}

void MockGetData(bool mockRet)
{
    g_mockGetDataRet = mockRet;
}
namespace OHOS {
namespace AppExecFwk {
FormCacheMgr::FormCacheMgr() {}

FormCacheMgr::~FormCacheMgr() {}

void FormCacheMgr::Start() {}

bool FormCacheMgr::DeleteData(const int64_t formId)
{
    return g_mockDeleteDataRet;
}

bool FormCacheMgr::NeedAcquireProviderData(const int64_t formId) const
{
    return g_mockIsExistRet;
}

bool FormCacheMgr::AddData(int64_t formId, const FormProviderData &formProviderData)
{
    return g_mockAddDataRet;
}

bool FormCacheMgr::GetData(int64_t formId, std::string &data,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    return g_mockGetDataRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
