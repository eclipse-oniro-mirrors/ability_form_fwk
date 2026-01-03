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

#include "form_mgr/form_edit_service.h"

#include "form_mgr_errors.h"
#include "ams_mgr/form_app_mgr_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "form_mgr/form_mgr_adapter.h"

namespace OHOS {
namespace AppExecFwk {
FormEditService::FormEditService()
{
    HILOG_DEBUG("call");
}
FormEditService::~FormEditService()
{
    HILOG_DEBUG("call");
}

ErrCode FormEditService::CloseFormEditAbility(const int32_t uid, bool isMainPage)
{
    std::string callerName;
    ErrCode ret = FormBmsHelper::GetInstance().GetBundleNameByUid(uid, callerName);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get bundleName by uid failed");
        return ret;
    }
    if (callerName.empty()) {
        HILOG_ERROR("bundleName empty");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    bool isForeground =
        FormAppMgrHelper::GetInstance().IsAbilityForeground(callerName, ExtensionAbilityType::FORM_EDIT);
    if (!isForeground) {
        HILOG_ERROR("form edit ability is not foreground");
        return ERR_APPEXECFWK_FORM_EDIT_UNSUPPORT_OPERATION;
    }

    auto requestMethod = String::Box(
        isMainPage ? Constants::PARAM_CLOSE_FORM_EDIT_VIEW : Constants::PARAM_CLOSE_FORM_EDIT_SEC_PAGE_VIEW);
    WantParams wantarams;
    wantarams.SetParam(Constants::PARMA_REQUEST_METHOD, requestMethod);
    wantarams.SetParam(
        Constants::PARAM_PAGE_ROUTER_SERVICE_CODE, Integer::Box(Constants::PAGE_ROUTER_SERVICE_CODE_FORM_EDIT));
    wantarams.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, String::Box(callerName));

    Want want;
    want.SetAction(Constants::FORM_PAGE_ACTION);
    want.SetBundle(callerName);
    want.SetParams(wantarams);
    return FormMgrAdapter::GetInstance().StartAbilityByFms(want);
}
}  // namespace AppExecFwk
}  // namespace OHOS
