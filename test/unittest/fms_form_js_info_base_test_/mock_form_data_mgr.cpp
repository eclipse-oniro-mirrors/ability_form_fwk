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

#include "data_center/form_data_mgr.h"

namespace {
    bool g_mockGetFormRecordRet = true;
    bool g_mockGetFormRecordParams = false;
    bool g_mockIsEnableRefreshRet = true;
}

void MockGetFormRecord(bool mockRet)
{
    g_mockGetFormRecordRet = mockRet;
}

void MockGetFormRecordParams(bool mockRet)
{
    g_mockGetFormRecordParams = mockRet;
}

void MockIsEnableRefresh(bool mockRet)
{
    g_mockIsEnableRefreshRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{}

FormDataMgr::~FormDataMgr()
{}

bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    if (g_mockGetFormRecordParams) {
        formRecord.isCountTimerRefresh = true;
    }

    return g_mockGetFormRecordRet;
}

bool FormDataMgr::IsEnableRefresh(int64_t formId)
{
    return g_mockIsEnableRefreshRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
