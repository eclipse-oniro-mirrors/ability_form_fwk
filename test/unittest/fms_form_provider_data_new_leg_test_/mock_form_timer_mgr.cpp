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

#include "common/timer_mgr/form_timer_mgr.h"

namespace {
    bool g_mockIsLimiterEnableRefreshRet = true;
}

void MockIsLimiterEnableRefresh(bool mockRet)
{
    g_mockIsLimiterEnableRefreshRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

FormTimerMgr::FormTimerMgr()
{}

FormTimerMgr::~FormTimerMgr()
{}

bool FormTimerMgr::IsLimiterEnableRefresh(int64_t formId)
{
    return g_mockIsLimiterEnableRefreshRet;
}

}  // namespace AppExecFwk
}  // namespace OHOS
