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
#include "connection_manager.h"
#include "fms_log_wrapper.h"
#include "form_errors.h"
#include "form_constants.h"
#include "form_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
const size_t LiveFormExtensionContext::CONTEXT_TYPE_ID(std::hash<const char *>{}("LiveFormExtensionContext"));
const std::string REQUEST_METHOD = "startAbilityByLiveForm";
const std::string TRANSPARENT_COLOR = "#00FFFFFF";
constexpr int32_t DEFAULT_ACCOUNT_ID = -1;

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
        HILOG_ERROR("SetBackgroundColor failed, ret=%{public}d", ret);
        return false;
    }
#endif // SUPPORT_SCREEN
    HILOG_DEBUG("SetWindowBackgroundColor end");
    return true;
}

ErrCode LiveFormExtensionContext::StartAbilityByFms(const AAFwk::Want &want, const std::string &formId)
{
    HILOG_INFO("StartAbilityByFms want: %{public}s", want.ToString().c_str());
    AAFwk::Want wantToHost(want);
    wantToHost.SetParam(Constants::PARAM_JSON_WANT_KEY, want.ToString());
    wantToHost.SetModuleName("");
    wantToHost.SetAction(Constants::FORM_PAGE_ACTION);
    wantToHost.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE, Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM);
    wantToHost.SetParam(Constants::PARMA_REQUEST_METHOD, REQUEST_METHOD);
    wantToHost.SetParam(Constants::PARAM_LIVE_FORM_ID_KEY, formId);
 
    HILOG_INFO("StartAbilityByFms wantToHost: %{public}s", wantToHost.ToString().c_str());
    ErrCode err = AppExecFwk::FormMgr::GetInstance().StartAbilityByFms(wantToHost);
    if (err != ERR_OK) {
        HILOG_ERROR("StartAbilityByFms fail, ret = %{public}d", err);
        return err;
    }
    HILOG_INFO("StartAbilityByFms success");
    return ERR_OK;
}

ErrCode LiveFormExtensionContext::StartAbilityByCall(const AAFwk::Want &want,
    const std::shared_ptr<CallerCallBack> &callback)
{
    HILOG_DEBUG("call");
    if (localCallContainer_ == nullptr) {
        localCallContainer_ = std::make_shared<LocalCallContainer>();
    }
    return localCallContainer_->StartAbilityByCallInner(want, callback, token_, DEFAULT_ACCOUNT_ID);
}

ErrCode LiveFormExtensionContext::ReleaseCall(const std::shared_ptr<CallerCallBack> &callback)
{
    HILOG_DEBUG("call");
    if (localCallContainer_ == nullptr) {
        HILOG_ERROR("null localCallContainer_");
        return ERR_INVALID_VALUE;
    }
    return localCallContainer_->ReleaseCall(callback);
}

void LiveFormExtensionContext::ClearFailedCallConnection(const std::shared_ptr<CallerCallBack> &callback)
{
    HILOG_DEBUG("call");
    if (localCallContainer_ == nullptr) {
        HILOG_ERROR("null localCallContainer_");
        return;
    }
    localCallContainer_->ClearFailedCallConnection(callback);
}
} // namespace AbilityRuntime
} // namespace OHOS