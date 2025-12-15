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

#include "form_edit_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "form_constants.h"
#include "form_mgr.h"


namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
void FormEditExtensionContext::SetWant(const std::shared_ptr<AAFwk::Want> &want)
{
    want_ = want;
    TAG_LOGD(AAFwkTag::UI_EXT, "Set want done");
}

ErrCode FormEditExtensionContext::StartAbilityByFms(const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StartAbilityByFms wantToHost: %{public}s", want.ToString().c_str());
    Want wantToHost(want);
    std::string requestMethod = "openFormEditSecPageView";
    wantToHost.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE, Constants::PAGE_ROUTER_SERVICE_CODE_FORM_EDIT);
    wantToHost.SetParam(Constants::PARMA_REQUEST_METHOD, requestMethod);
    wantToHost.SetAction(Constants::FORM_PAGE_ACTION);

    TAG_LOGI(AAFwkTag::UI_EXT, "StartAbilityByFms wantToHost: %{public}s", wantToHost.ToString().c_str());
    ErrCode err = AppExecFwk::FormMgr::GetInstance().StartAbilityByFms(wantToHost);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret = %{public}d", err);
        return err;
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "StartAbilityByFms success");
    return ERR_OK;
}

ErrCode FormEditExtensionContext::StartUIAbilityByFms(const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StartUIAbilityByFms ability: %{public}s", want.GetElement().GetAbilityName().c_str());
    ErrCode err = AppExecFwk::FormMgr::GetInstance().StartUIAbilityByFms(want);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret = %{public}d", err);
        return err;
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "StartUIAbilityByFms success");
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS