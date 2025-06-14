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

#include "form_refresh/strategy/refresh_exec_mgr.h"

#include "form_provider/form_provider_mgr.h"
#include "form_render/form_render_mgr.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode RefreshExecMgr::AskForProviderData(const int64_t formId, const FormRecord &record, const Want &want)
{
    HILOG_INFO("call, formId:%{public} " PRId64, formId);
    return FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, record, want);
}

ErrCode RefreshExecMgr::UpdateByProviderData(
    const int64_t formId, const FormProviderData &formProviderData, bool mergeData)
{
    HILOG_INFO("call, formId:%{public} " PRId64, formId);
    WantParams wantParams;
    return FormRenderMgr::GetInstance().UpdateRenderingForm(formId, formProviderData, wantParams, mergeData);
}

} // namespace AppExecFwk
} // namespace OHOS