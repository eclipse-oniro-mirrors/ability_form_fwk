/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include "form_mgr_errors.h"
#include "form_renderer_group.h"

namespace {
    bool g_mockIsFormRequestsEmpty = true;
}

void MockIsFormRequestsEmpty(bool mockRet)
{
    g_mockIsFormRequestsEmpty = mockRet;
}

namespace OHOS {
namespace Ace {
void FormRendererGroup::AddForm(const OHOS::AAFwk::Want& want, const OHOS::AppExecFwk::FormJsInfo& formJsInfo)
{
    return;
}

void FormRendererGroup::OnUnlock()
{
    return;
}

void FormRendererGroup::UpdateForm(const OHOS::AppExecFwk::FormJsInfo& formJsInfo)
{
    return;
}

void FormRendererGroup::DeleteForm()
{
    return;
}

void FormRendererGroup::DeleteForm(const std::string& compId)
{
    return;
}

void FormRendererGroup::ReloadForm(const AppExecFwk::FormJsInfo& formJsInfo)
{
    return;
}

void FormRendererGroup::UpdateConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    return;
}

bool FormRendererGroup::IsFormRequestsEmpty()
{
    return g_mockIsFormRequestsEmpty;
}

void FormRendererGroup::RecycleForm(std::string& statusData) const
{
    return;
}

void FormRendererGroup::RecoverRenderer(const std::vector<FormRequest>& formRequests, size_t currentCompIndex)
{
    return;
}
}  // namespace Ace
}  // namespace OHOS
