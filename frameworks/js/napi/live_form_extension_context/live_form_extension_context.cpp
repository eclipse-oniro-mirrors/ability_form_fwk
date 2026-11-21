/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "display_manager.h"
#include "display_info.h"
#include "fms_log_wrapper.h"
#include "napi_form_util.h"
#include "form_errors.h"
#include "form_constants.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"

#include <cmath>
#include <limits>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
const size_t LiveFormExtensionContext::contextTypeId(std::hash<const char *>{}("LiveFormExtensionContext"));
const std::string TRANSPARENT_COLOR = "#00FFFFFF";
constexpr float MAX_LAYOUT_SCALE = 100.0f;

bool LiveFormExtensionContext::SetWindowBackgroundColor()
{
    HILOG_DEBUG("SetWindowBackgroundColor begin");
#ifdef SUPPORT_SCREEN
    sptr<Rosen::Window> uiWindow = UIExtensionContext::GetWindow();
    if (uiWindow == nullptr) {
        HILOG_ERROR("null uiWindow");
        return false;
    }

    Rosen::WMError ret = uiWindow->SetBackgroundColor(TRANSPARENT_COLOR);
    if (ret != Rosen::WMError::WM_OK) {
        HILOG_ERROR("SetBackgroundColor failed,ret=%{public}d", ret);
        return false;
    }
#endif // SUPPORT_SCREEN
    HILOG_DEBUG("SetWindowBackgroundColor end");
    return true;
}

ErrCode LiveFormExtensionContext::SetUIExtCustomDensity(float layoutScale)
{
    HILOG_DEBUG("SetUIExtCustomDensity begin");
#ifdef SUPPORT_SCREEN
    sptr<Rosen::Window> uiWindow = UIExtensionContext::GetWindow();
    if (uiWindow == nullptr) {
        HILOG_ERROR("SetUIExtCustomDensity null uiWindow");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (std::islessequal(layoutScale, 0.0f) || std::isgreaterequal(layoutScale, MAX_LAYOUT_SCALE)) {
        HILOG_ERROR("layoutScale out of range (0,%{public}f),layoutScale:%{public}f", MAX_LAYOUT_SCALE, layoutScale);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    HILOG_INFO("SetUIExtCustomDensity layoutScale:%{public}f", layoutScale);

    auto defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (defaultDisplay == nullptr) {
        HILOG_ERROR("SetUIExtCustomDensity get defaultDisplay failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    auto displayInfo = defaultDisplay->GetDisplayInfo();
    if (displayInfo == nullptr) {
        HILOG_ERROR("SetUIExtCustomDensity get displayInfo failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    float density = displayInfo->GetDensityInCurResolution();
    if (density > 0.0f && layoutScale > std::numeric_limits<float>::max() / density) {
        HILOG_ERROR("layoutScale too large,would cause overflow:layoutScale:%{public}f,density:%{public}f",
            layoutScale, density);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    density = density * layoutScale;
    Rosen::WMError ret = uiWindow->SetUIExtCustomDensity(density);
    if (ret != Rosen::WMError::WM_OK) {
        HILOG_ERROR("SetUIExtCustomDensity failed,ret=%{public}d", ret);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
#endif // SUPPORT_SCREEN
    HILOG_DEBUG("SetUIExtCustomDensity end");
    return ERR_OK;
}

ErrCode LiveFormExtensionContext::OpenLiveFormPage(const AAFwk::Want &want, const std::string &formId)
{
    HILOG_INFO("OpenLiveFormPage want:%{private}s", want.ToString().c_str());
    AAFwk::Want wantToHost;
    ElementName elementName = want.GetElement();
    wantToHost.SetElementName(elementName.GetBundleName(), elementName.GetAbilityName());
    wantToHost.SetParam(Constants::PARAM_JSON_WANT_KEY, want.GetStringParam(Constants::PARAM_JSON_WANT_KEY));

    HILOG_INFO("OpenLiveFormPage wantToHost:%{private}s", wantToHost.ToString().c_str());
    ErrCode err = AppExecFwk::FormMgr::GetInstance().OpenLiveFormPage(wantToHost, formId);
    if (err != ERR_OK) {
        HILOG_ERROR("OpenLiveFormPage fail,ret = %{public}d", err);
        return err;
    }
    HILOG_INFO("OpenLiveFormPage success");
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS