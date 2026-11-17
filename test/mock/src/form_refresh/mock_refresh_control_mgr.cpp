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

#include "form_refresh/mock_refresh_control_mgr.h"
#include <gtest/gtest.h>
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "fms_log_wrapper.h"

namespace {
    bool g_mockIsFormInvisibleRet = false;
    bool g_mockIsHealthyControlRet = false;
    bool g_mockIsScreenOffRet = false;
    bool g_mockIsNeedToFreshRet = true;
    bool g_mockIsAddFormFinishRet = true;
}

namespace OHOS {
namespace AppExecFwk {
void MockRefreshControlMgr::MockIsFormInvisible(bool mockRet)
{
    g_mockIsFormInvisibleRet = mockRet;
}

void MockRefreshControlMgr::MockIsHealthyControl(bool mockRet)
{
    g_mockIsHealthyControlRet = mockRet;
}

void MockRefreshControlMgr::MockIsScreenOff(bool mockRet)
{
    g_mockIsScreenOffRet = mockRet;
}

void MockRefreshControlMgr::MockIsNeedToFresh(bool mockRet)
{
    g_mockIsNeedToFreshRet = mockRet;
}

void MockRefreshControlMgr::MockIsAddFormFinish(bool mockRet)
{
    g_mockIsAddFormFinishRet = mockRet;
}

RefreshControlMgr::RefreshControlMgr() {}
RefreshControlMgr::~RefreshControlMgr() {}

bool RefreshControlMgr::IsFormInvisible(const FormRecord &record)
{
    GTEST_LOG_(INFO) << "RefreshControlMgr::IsFormInvisible called, returning " << g_mockIsFormInvisibleRet;
    return g_mockIsFormInvisibleRet;
}

bool RefreshControlMgr::IsHealthyControl(const FormRecord &record)
{
    GTEST_LOG_(INFO) << "RefreshControlMgr::IsHealthyControl called, returning " << g_mockIsHealthyControlRet;
    return g_mockIsHealthyControlRet;
}

bool RefreshControlMgr::IsScreenOff(const FormRecord &record)
{
    GTEST_LOG_(INFO) << "RefreshControlMgr::IsScreenOff called, returning " << g_mockIsScreenOffRet;
    return g_mockIsScreenOffRet;
}

bool RefreshControlMgr::IsNeedToFresh(FormRecord &record, bool isVisibleToFresh)
{
    GTEST_LOG_(INFO) << "RefreshControlMgr::IsNeedToFresh called, returning " << g_mockIsNeedToFreshRet;
    return g_mockIsNeedToFreshRet;
}

bool RefreshControlMgr::IsAddFormFinish(const int64_t formId)
{
    GTEST_LOG_(INFO) << "RefreshControlMgr::IsAddFormFinish called, returning " << g_mockIsAddFormFinishRet;
    return g_mockIsAddFormFinishRet;
}
}  // namespace AppExecFwk
}  // namespace OHOS
