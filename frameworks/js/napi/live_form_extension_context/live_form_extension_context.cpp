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

#include "live_form_extension_context.h"
#include "fms_log_wrapper.h"
#include "form_errors.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
const size_t LiveFormExtensionContext::CONTEXT_TYPE_ID(std::hash<const char *>{}("LiveFormExtensionContext"));

int32_t LiveFormExtensionContext::SendData(const AAFwk::WantParams &params)
{
    HILOG_DEBUG("SendData begin");
#ifdef SUPPORT_SCREEN
    sptr<Rosen::Window> uiWindow = UIExtensionContext::GetWindow();
    if (uiWindow == nullptr) {
        HILOG_ERROR("null uiWindow");
        return ERR_FORM_EXTERNAL_SET_OPERATION_FAILED;
    }

    Rosen::WMError ret = uiWindow->TransferExtensionData(params);
    if (ret != Rosen::WMError::WM_OK) {
        HILOG_ERROR("TransferExtensionData failed, ret=%{public}d", ret);
        return ERR_FORM_EXTERNAL_SET_OPERATION_FAILED;
    }
#endif // SUPPORT_SCREEN
    HILOG_DEBUG("SendData end");
    return ERR_OK;
}

bool LiveFormExtensionContext::SetWindowBackgroundColor(const char *color)
{
    HILOG_DEBUG("SetWindowBackgroundColor begin");
#ifdef SUPPORT_SCREEN
    sptr<Rosen::Window> uiWindow = UIExtensionContext::GetWindow();
    if (uiWindow == nullptr) {
        HILOG_ERROR("null uiWindow");
        return false;
    }

    Rosen::WMError ret = uiWindow->SetBackgroundColor(color);
    if (ret != Rosen::WMError::WM_OK) {
        HILOG_ERROR("SetBackgroundColor failed, ret=%{public}d", ret);
        return false;
    }
#endif // SUPPORT_SCREEN
    HILOG_DEBUG("SetWindowBackgroundColor end");
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS