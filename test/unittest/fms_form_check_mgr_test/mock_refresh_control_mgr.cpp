/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "form_refresh/strategy/refresh_control_mgr.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    bool g_mockIsSystemOverload = false;
    bool g_mockIsFormInvisible = false;
    bool g_mockIsScreenOff = false;
    bool g_mockIsHealthyControl = false;
    bool g_mockIsNeedToFresh = true;
}

namespace OHOS {
void MockIsSystemOverload(bool mockBool)
{
    g_mockIsSystemOverload = mockBool;
}

void MockIsFormInvisible(bool mockBool)
{
    g_mockIsFormInvisible = mockBool;
}

void MockIsScreenOff(bool mockBool)
{
    g_mockIsScreenOff = mockBool;
}

void MockIsHealthyControl(bool mockBool)
{
    g_mockIsHealthyControl = mockBool;
}

void MockIsNeedToFresh(bool mockBool)
{
    g_mockIsNeedToFresh = mockBool;
}
}

namespace OHOS {
namespace AppExecFwk {

RefreshControlMgr::RefreshControlMgr() {}
RefreshControlMgr::~RefreshControlMgr() {}

bool RefreshControlMgr::IsSystemOverload()
{
    return g_mockIsSystemOverload;
}

bool RefreshControlMgr::IsFormInvisible(const FormRecord &record)
{
    return g_mockIsFormInvisible;
}

bool RefreshControlMgr::IsScreenOff(const FormRecord &record)
{
    return g_mockIsScreenOff;
}

bool RefreshControlMgr::IsHealthyControl(const FormRecord &record)
{
    return g_mockIsHealthyControl;
}

bool RefreshControlMgr::IsNeedToFresh(FormRecord &record, bool isVisibleToFresh)
{
    return g_mockIsNeedToFresh;
}
} // namespace AppExecFwk
} // namespace OHOS
