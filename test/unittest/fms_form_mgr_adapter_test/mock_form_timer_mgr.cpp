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

#include "form_timer_mgr.h"

namespace {
    bool g_mockRemoveFormTimerRet = true;
    bool g_mockGetIntervalTimerRet = true;
    bool g_mockGetUpdateAtTimerRet = true;
    bool g_mockGetDynamicItemRet = true;
}

void MockRemoveFormTimer(bool mockRet)
{
    g_mockRemoveFormTimerRet = mockRet;
}

void MockGetIntervalTimer(bool mockRet)
{
    g_mockGetIntervalTimerRet = mockRet;
}

void MockGetUpdateAtTimer(bool mockRet)
{
    g_mockGetUpdateAtTimerRet = mockRet;
}

void MockGetDynamicItem(bool mockRet)
{
    g_mockGetDynamicItemRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
bool FormTimerMgr::RemoveFormTimer(int64_t formId)
{
    return g_mockRemoveFormTimerRet;
}

bool FormTimerMgr::GetIntervalTimer(int64_t formId, FormTimer &formTimer)
{
    return g_mockGetIntervalTimerRet;
}

bool FormTimerMgr::GetUpdateAtTimer(int64_t formId, UpdateAtItem &updateAtItem)
{
    return g_mockGetUpdateAtTimerRet;
}

bool FormTimerMgr::GetDynamicItem(int64_t formId, DynamicRefreshItem &dynamicItem)
{
    return g_mockGetDynamicItemRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
