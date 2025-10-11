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

#include "form_host_caller.h"

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_host_client.h"
#include "form_mgr_errors.h"
#include "form_provider_interface.h"

namespace OHOS {
namespace AppExecFwk {
void FormHostCallerRecipient::OnRemoteDied(const wptr<IRemoteObject> &__attribute__((unused)) remote)
{
    HILOG_DEBUG("On remote died");
    if (handler_ != nullptr) {
        handler_(remote);
    }
}

void FormHostCaller::UpdateForm(int64_t formId, const FormProviderData &formProviderData)
{
    HILOG_DEBUG("call");
    FormJsInfo formJsInfo = formJsInfo_;
    formJsInfo.formData = formProviderData.GetDataString();
    formJsInfo.formProviderData = formProviderData;
    if (!formJsInfo.ConvertRawImageData()) {
        HILOG_ERROR("convert raw image data failed");
    }
    FormHostClient::GetInstance()->UpdateForm(formJsInfo);
}

ErrCode FormHostCaller::RequestForm(int64_t formId, const sptr<IRemoteObject> &callerToken, const AAFwk::Want &want)
{
    sptr<IFormProvider> providerToken = iface_cast<IFormProvider>(callerToken_);
    if (providerToken == nullptr) {
        HILOG_ERROR("null callerToken formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return providerToken->NotifyFormUpdate(formId, want, callerToken);
}

ErrCode FormHostCaller::MessageEvent(int64_t formId, const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken)
{
    std::string message = want.GetStringParam(Constants::PARAM_MESSAGE_KEY);
    sptr<IFormProvider> providerToken = iface_cast<IFormProvider>(callerToken_);
    if (providerToken == nullptr) {
        HILOG_ERROR("null callerToken formId: %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return providerToken->FireFormEvent(formId, message, want, callerToken);
}

bool FormHostCaller::IsSameToken(const sptr<IRemoteObject> &callerToken) const
{
    return (callerToken == callerToken_);
}

void FormHostCaller::AddDeathRecipient(sptr<IRemoteObject::DeathRecipient> deathRecipient)
{
    HILOG_DEBUG("call");
    if (callerToken_ == nullptr) {
        HILOG_ERROR("callerToken_ is null");
        return;
    }
    callerToken_->AddDeathRecipient(deathRecipient);
}
} // namespace AppExecFwk
} // namespace OHOS
