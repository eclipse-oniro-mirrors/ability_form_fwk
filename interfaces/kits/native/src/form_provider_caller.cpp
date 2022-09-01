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

#include "form_provider_caller.h"

#include <cinttypes>

#include "form_constants.h"
#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
sptr<IRemoteObject> FormProviderCaller::GetCallerToken() const
{
    return callerToken_;
}

void FormProviderCaller::AddForm(const FormJsInfo &formJsInfo)
{
    std::lock_guard<std::recursive_mutex> lock(formJsInfoMutex_);
    formJsInfoMap_[formJsInfo.formId] = formJsInfo;
}

void FormProviderCaller::DeleteForm(int64_t formId)
{
    std::lock_guard<std::recursive_mutex> lock(formJsInfoMutex_);
    formJsInfoMap_.erase(formId);
}

bool FormProviderCaller::GetFormJsInfo(int64_t formId, FormJsInfo &formJsInfo)
{
    std::lock_guard<std::recursive_mutex> lock(formJsInfoMutex_);
    if (formJsInfoMap_.find(formId) != formJsInfoMap_.end()) {
        formJsInfo = formJsInfoMap_[formId];
        return true;
    }
    HILOG_ERROR("%{public}s error, get form js info failed.", __func__);
    return false;
}

bool FormProviderCaller::HasForm(int64_t formId)
{
    std::lock_guard<std::recursive_mutex> lock(formJsInfoMutex_);
    return (formJsInfoMap_.find(formId) != formJsInfoMap_.end());
}

bool FormProviderCaller::IsFormEmpty()
{
    std::lock_guard<std::recursive_mutex> lock(formJsInfoMutex_);
    return formJsInfoMap_.empty();
}

int32_t FormProviderCaller::OnAcquire(const FormProviderInfo &formProviderInfo, const AAFwk::Want &want,
    const sptr<IRemoteObject> &token)
{
    std::string strFormId = want.GetStringParam(Constants::PARAM_FORM_IDENTITY_KEY);
    if (strFormId.empty()) {
        HILOG_ERROR("%{public}s error, formId is empty.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    int64_t formId = std::stoll(strFormId);
    int type = want.GetIntParam(Constants::ACQUIRE_TYPE, 0);
    HILOG_DEBUG("%{public}s come: formId is %{public}" PRId64 ", type is %{public}d", __func__, formId, type);

    auto formProviderData = formProviderInfo.GetFormData();
    formProviderData.ConvertRawImageData();
    FormJsInfo formJsInfo;
    GetFormJsInfo(formId, formJsInfo);
    formJsInfo.formData = formProviderData.GetDataString();
    formJsInfo.formProviderData = formProviderData;
    if (type == Constants::ACQUIRE_TYPE_CREATE_FORM) {
        return OnAcquired(formJsInfo, token);
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

int32_t FormProviderCaller::OnAcquired(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &token)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    sptr<IFormHost> callerToken = iface_cast<IFormHost>(callerToken_);
    if (callerToken == nullptr) {
        HILOG_ERROR("%{public}s error, callerToken is nullptr.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    callerToken->OnAcquired(formJsInfo, token);
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
