/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_free_install_operator.h"
#include "form_bms_helper.h"
#include "form_mgr_errors.h"
#include "form_share_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormFreeInstallOperator::FormFreeInstallOperator(const std::string &formShareInfoKey,
    const std::shared_ptr<FormEventHandler> &handler)
    : formShareInfoKey_(formShareInfoKey), handler_(handler)
{
}

FormFreeInstallOperator::~FormFreeInstallOperator()
{
    freeInstallStatusCallBack_ = nullptr;
}

int32_t FormFreeInstallOperator::StartFreeInstall(
    const std::string &bundleName, const std::string &moduleName, const std::string &abilityName)
{
    HILOG_DEBUG("%{public}s called, bundleName: %{public}s, abilityName: %{public}s",
        __func__, bundleName.c_str(), abilityName.c_str());

    freeInstallStatusCallBack_ = new (std::nothrow) FreeInstallStatusCallBack(weak_from_this());
    if (freeInstallStatusCallBack_ == nullptr) {
        HILOG_ERROR("new FreeInstallStatusCallBack failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    Want want;
    want.SetElementName(bundleName, abilityName);
    want.SetModuleName(moduleName);
    AbilityInfo abilityInfo = {};
    constexpr auto flag = AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION;
    if (iBundleMgr->QueryAbilityInfo(
        want, flag, FormUtil::GetCurrentAccountId(), abilityInfo, freeInstallStatusCallBack_)) {
        HILOG_DEBUG("The app has installed.");
    }

    return ERR_OK;
}

void FormFreeInstallOperator::OnInstallFinished(int32_t resultCode)
{
    HILOG_DEBUG("%{public}s called, resultCode: %{public}d", __func__, resultCode);
    if (handler_ == nullptr) {
        return;
    }
    auto self = shared_from_this();
    auto task = [self, resultCode]() {
        DelayedSingleton<FormShareMgr>::GetInstance()->OnInstallFinished(self, resultCode, self->formShareInfoKey_);
    };
    handler_->PostTask(task);
}

FreeInstallStatusCallBack::FreeInstallStatusCallBack(
    const std::weak_ptr<FormFreeInstallOperator> &freeInstallOperator)
    : formFreeInstallOperator_(freeInstallOperator)
{
}

void FreeInstallStatusCallBack::OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId)
{
    HILOG_DEBUG("%{public}s called, resultCode:%{public}d.", __func__, resultCode);

    auto freeInstallOperator = formFreeInstallOperator_.lock();
    if (freeInstallOperator == nullptr) {
        HILOG_ERROR("freeInstallOperator is nullptr");
        return;
    }
    freeInstallOperator->OnInstallFinished(resultCode);
    HILOG_DEBUG("%{public}s end.", __func__);
}
} // namespace AppExecFwk
} // namespace OHOS
