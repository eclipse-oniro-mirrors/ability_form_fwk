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

#include "form_refresh/mock_refresh_cache_mgr.h"
#include <gtest/gtest.h>
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "fms_log_wrapper.h"

namespace {
    int g_addFlagByInvisibleCallCount = 0;
    int64_t g_lastFormId = 0;
    int32_t g_lastConditionType = 0;
}

namespace OHOS {
namespace AppExecFwk {
void MockRefreshCacheMgr::MockAddFlagByInvisible()
{
    g_addFlagByInvisibleCallCount = 0;
    g_lastFormId = 0;
    g_lastConditionType = 0;
}

RefreshCacheMgr::RefreshCacheMgr() {}
RefreshCacheMgr::~RefreshCacheMgr() {}

void RefreshCacheMgr::AddFlagByInvisible(int64_t formId, int32_t conditionType)
{
    GTEST_LOG_(INFO) << "RefreshCacheMgr::AddFlagByInvisible called with formId " << formId <<
        ", conditionType " << conditionType;
    g_addFlagByInvisibleCallCount++;
    g_lastFormId = formId;
    g_lastConditionType = conditionType;
}
}  // namespace AppExecFwk
}  // namespace OHOS
