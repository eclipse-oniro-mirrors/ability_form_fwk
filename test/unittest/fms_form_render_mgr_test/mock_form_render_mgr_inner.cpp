/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_render_mgr_inner.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockRenderForm = true;
    bool g_mockUpdateRenderingForm = true;
    bool g_mockStopRenderingForm = true;
    bool g_mockReleaseRenderer = true;
    bool g_mockAddConnection = true;
}

void MockRenderForm(bool mockRet)
{
    g_mockRenderForm = mockRet;
}

void MockUpdateRenderingForm(bool mockRet)
{
    g_mockUpdateRenderingForm = mockRet;
}

void MockStopRenderingForm(bool mockRet)
{
    g_mockStopRenderingForm = mockRet;
}

void MockReleaseRenderer(bool mockRet)
{
    g_mockReleaseRenderer = mockRet;
}

void MockAddConnection(bool mockRet)
{
    g_mockAddConnection = mockRet;
}


namespace OHOS {
namespace AppExecFwk {
ErrCode FormRenderMgrInner::RenderForm(
    const FormRecord &formRecord, Want &want, const sptr<IRemoteObject> &hostToken)
{
    if (g_mockRenderForm) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::UpdateRenderingForm(FormRecord &formRecord, const FormProviderData &formProviderData,
    const WantParams &wantParams, bool mergeData)
{
    if (g_mockUpdateRenderingForm) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::StopRenderingForm(int64_t formId, const FormRecord &formRecord,
    const std::string &compId, const sptr<IRemoteObject> &hostToken)
{
    if (g_mockStopRenderingForm) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::ReloadForm(const std::vector<FormRecord> &&formRecords,
    const std::string &bundleName, int32_t userId)
{
    if (g_mockReleaseRenderer) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::AddConnection(int64_t formId, sptr<FormRenderConnection> connection)
{
    if (g_mockAddConnection) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}
}  // namespace AppExecFwk
}  // namespace OHOS
