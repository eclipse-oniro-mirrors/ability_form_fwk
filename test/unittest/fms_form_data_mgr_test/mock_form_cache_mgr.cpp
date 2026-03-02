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

namespace {
    bool g_mockGetDataRet = true;
    std::string g_mockDataString = "";
}

void MockGetData(int64_t formId, bool ret)
{
    g_mockGetDataRet = ret;
}

void MockGetData(int64_t formId, bool ret, const std::string &data)
{
    g_mockGetDataRet = ret;
    g_mockDataString = data;
}

namespace OHOS {
namespace AppExecFwk {
bool FormCacheMgr::GetData(int64_t formId, std::string &data,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    data = g_mockDataString;
    return g_mockGetDataRet;
}
} // namespace AppExecFwk
} // namespace OHOS
