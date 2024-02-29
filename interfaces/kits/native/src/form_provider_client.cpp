/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_provider_client.h"

#include <cinttypes>
#include <memory>
#include <type_traits>
#include <unistd.h>

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_caller_mgr.h"
#include "form_supply_proxy.h"
#include "ipc_skeleton.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
int FormProviderClient::AcquireProviderFormInfo(
    const FormJsInfo &formJsInfo,
    const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");

    Want newWant(want);
    newWant.SetParam(Constants::ACQUIRE_TYPE, want.GetIntParam(Constants::ACQUIRE_TYPE, 0));
    newWant.SetParam(Constants::FORM_CONNECT_ID, want.GetIntParam(Constants::FORM_CONNECT_ID, 0));
    newWant.SetParam(Constants::FORM_SUPPLY_INFO, want.GetStringParam(Constants::FORM_SUPPLY_INFO));
    newWant.SetParam(Constants::PROVIDER_FLAG, true);
    newWant.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formJsInfo.formId));
    std::shared_ptr<Ability> ownerAbility = GetOwner();
    if (ownerAbility == nullptr) {
        HILOG_ERROR("Owner is nullptr.");
        FormProviderInfo formProviderInfo;
        newWant.SetParam(Constants::PROVIDER_FLAG, ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);
        return HandleAcquire(formProviderInfo, newWant, callerToken);
    }

    HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());

    if (!CheckIsSystemApp()) {
        HILOG_WARN("Permission denied.");
        FormProviderInfo formProviderInfo;
        newWant.SetParam(Constants::PROVIDER_FLAG, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
        return HandleAcquire(formProviderInfo, newWant, callerToken);
    }

    Want createWant(want);
    createWant.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(formJsInfo.formId));
    createWant.RemoveParam(Constants::FORM_CONNECT_ID);
    createWant.RemoveParam(Constants::ACQUIRE_TYPE);
    createWant.RemoveParam(Constants::FORM_SUPPLY_INFO);
    createWant.RemoveParam(Constants::PARAM_FORM_HOST_TOKEN);
    createWant.RemoveParam(Constants::FORM_COMP_ID);
    createWant.RemoveParam(Constants::FORM_DENSITY);
    createWant.RemoveParam(Constants::FORM_PROCESS_ON_ADD_SURFACE);
    createWant.RemoveParam(Constants::FORM_ALLOW_UPDATE);
    if (!createWant.HasParameter(Constants::LAUNCH_REASON_KEY)) {
        createWant.SetParam(Constants::LAUNCH_REASON_KEY, Constants::FORM_DEFAULT);
    }
    if (!createWant.HasParameter(Constants::PARAM_FORM_CUSTOMIZE_KEY)) {
        std::vector<std::string> customizeData;
        createWant.SetParam(Constants::PARAM_FORM_CUSTOMIZE_KEY, customizeData);
    }
    FormProviderInfo formProviderInfo = ownerAbility->OnCreate(createWant);
    HILOG_DEBUG("formId: %{public}" PRId64 ", data: %{private}s", formJsInfo.formId,
        formProviderInfo.GetFormDataString().c_str());
    if (newWant.HasParameter(Constants::PARAM_FORM_HOST_TOKEN)) {
        HandleRemoteAcquire(formJsInfo, formProviderInfo, newWant, AsObject());
    }
    return HandleAcquire(formProviderInfo, newWant, callerToken);
}

int FormProviderClient::NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        auto hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
        if (hostToken != nullptr) {
            FormCallerMgr::GetInstance().RemoveFormProviderCaller(formId, hostToken);
            break;
        }

        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is null.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }

        if (!CheckIsSystemApp()) {
            HILOG_WARN("Permission denied");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        ownerAbility->OnDelete(formId);
    } while (false);

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::NotifyFormsDelete(
    const std::vector<int64_t> &formIds,
    const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is nullptr");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }
        if (!CheckIsSystemApp()) {
            HILOG_WARN("Permission denied");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("formIds size = %{public}zu, abilityName is %{public}s.", formIds.size(),
            ownerAbility->GetAbilityName().c_str());
        for (int64_t formId : formIds) {
            ownerAbility->OnDelete(formId);
        }
    } while (false);

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::NotifyFormUpdate(
    const int64_t formId,
    const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("NotifyFormUpdate start.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is null.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }

        if (!CheckIsSystemApp() && !IsCallBySelfBundle()) {
            HILOG_ERROR("Permission denied.");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        ownerAbility->OnUpdate(formId, want.GetParams());
    } while (false);

    if (!want.HasParameter(Constants::FORM_CONNECT_ID)) {
        return errorCode;
    }

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::EventNotify(
    const std::vector<int64_t> &formIds,
    const int32_t formVisibleType, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("EventNotify start.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is nullptr.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }

        if (!CheckIsSystemApp()) {
            HILOG_WARN("Permission denied.");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        std::map<int64_t, int32_t> formEventsMap;
        for (const auto &formId : formIds) {
            formEventsMap.insert(std::make_pair(formId, formVisibleType));
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        ownerAbility->OnVisibilityChanged(formEventsMap);
    } while (false);

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::NotifyFormCastTempForm(
    const int64_t formId,
    const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("NotifyFormCastTempForm start.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is nullptr.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }

        if (!CheckIsSystemApp()) {
            HILOG_WARN("Permission denied");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        ownerAbility->OnCastTemptoNormal(formId);
    } while (false);

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::FireFormEvent(
    const int64_t formId,
    const std::string &message,
    const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("FireFormEvent start.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is nullptr.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }

        if (!CheckIsSystemApp() && !IsCallBySelfBundle()) {
            HILOG_WARN("Permission denied");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        ownerAbility->OnTriggerEvent(formId, message);
    } while (false);

    if (!want.HasParameter(Constants::FORM_CONNECT_ID)) {
        return errorCode;
    }

    return DCRtnHelper(errorCode, want, callerToken);
}

int FormProviderClient::AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
                                     const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("called.");

    // The error code for business operation.
    int errorCode = ERR_OK;
    FormState state = FormState::UNKNOWN;
    do {
        std::shared_ptr<Ability> ownerAbility = GetOwner();
        if (ownerAbility == nullptr) {
            HILOG_ERROR("Owner is nullptr.");
            errorCode = ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
            break;
        }
        if (!CheckIsSystemApp()) {
            HILOG_ERROR("Permission denied");
            errorCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
            break;
        }

        HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
        state = ownerAbility->OnAcquireFormState(wantArg);
    } while (false);

    HandleAcquireStateResult(state, provider, wantArg, want, callerToken);
    return errorCode;
}

void FormProviderClient::SetOwner(const std::shared_ptr<Ability> ability)
{
    if (ability == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(abilityMutex_);
    owner_ = ability;
}

void FormProviderClient::ClearOwner(const std::shared_ptr<Ability> ability)
{
    if (ability == nullptr) {
        return;
    }

    std::lock_guard<std::mutex> lock(abilityMutex_);
    if (!owner_.expired()) {
        std::shared_ptr<Ability> ownerAbility = owner_.lock();
        if (ability == ownerAbility) {
            owner_.reset();
        }
    }
}

std::shared_ptr<Ability> FormProviderClient::GetOwner()
{
    std::shared_ptr<Ability> ownerAbility = nullptr;
    std::lock_guard<std::mutex> lock(abilityMutex_);
    if (!owner_.expired()) {
        ownerAbility = owner_.lock();
    }
    return ownerAbility;
}

bool FormProviderClient::CheckIsSystemApp() const
{
    HILOG_DEBUG("called.");

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid > Constants::MAX_SYSTEM_APP_UID) {
        HILOG_WARN("callingUid is %{public}d, which is larger than %{public}d.", callingUid,
            Constants::MAX_SYSTEM_APP_UID);
        return false;
    }

    HILOG_DEBUG("callingUid is %{public}d.", callingUid);
    return true;
}

int FormProviderClient::HandleAcquire(
    const FormProviderInfo &formProviderInfo,
    const Want &newWant,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("Image state is %{public}d.", formProviderInfo.GetFormData().GetImageDataState());
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("IFormSupply is nullptr.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    formSupplyClient->OnAcquire(formProviderInfo, newWant);
    return ERR_OK;
}

int FormProviderClient::DCRtnHelper(const int &errCode, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    // The error code for disconnect.
    int disconnectErrorCode = HandleDisconnect(want, callerToken);
    if (errCode != ERR_OK) {
        // If errorCode is not ERR_OK，return errorCode.
        return errCode;
    }
    return disconnectErrorCode;
}

int  FormProviderClient::HandleDisconnect(const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("ConnectId: %{public}d.", want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("IFormSupply is nullptr.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    formSupplyClient->OnEventHandle(want);
    return ERR_OK;
}

int FormProviderClient::HandleAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
                                                 const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("Form state is %{public}d", state);
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("IFormSupply is nullptr.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    formSupplyClient->OnAcquireStateResult(state, provider, wantArg, want);
    return ERR_OK;
}

int32_t FormProviderClient::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const sptr<IRemoteObject> &formSupplyCallback, int64_t requestCode)
{
    HILOG_DEBUG("called.");
    if (formId <= 0 || remoteDeviceId.empty() || formSupplyCallback == nullptr || requestCode <= 0) {
        HILOG_ERROR("Abnormal parameters exist.");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }

    std::shared_ptr<Ability> ownerAbility = GetOwner();
    if (ownerAbility == nullptr) {
        HILOG_ERROR("Owner is nullptr.");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }

    HILOG_INFO("Ability name is %{public}s.", ownerAbility->GetAbilityName().c_str());
    if (!CheckIsSystemApp()) {
        HILOG_WARN("Permission denied.");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    }

    auto formCall = iface_cast<IFormSupply>(formSupplyCallback);
    if (formCall == nullptr) {
        HILOG_ERROR("IFormSupply is nullptr.");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }

    AAFwk::WantParams wantParams;
    auto result = ownerAbility->OnShare(formId, wantParams);
    formCall->OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);

    HILOG_DEBUG("end");
    return ERR_OK;
}

void FormProviderClient::HandleRemoteAcquire(const FormJsInfo &formJsInfo, const FormProviderInfo &formProviderInfo,
    const Want &want, const sptr<IRemoteObject> &token)
{
    HILOG_DEBUG("called.");
    auto hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    if (hostToken == nullptr) {
        HILOG_ERROR("Host token is invalid.");
        return;
    }
    FormCallerMgr::GetInstance().AddFormProviderCaller(formJsInfo, hostToken);

    std::vector<std::shared_ptr<FormProviderCaller>> formProviderCallers;
    FormCallerMgr::GetInstance().GetFormProviderCaller(formJsInfo.formId, formProviderCallers);
    for (const auto &formProviderCaller : formProviderCallers) {
        formProviderCaller->OnAcquire(formProviderInfo, want, token);
    }
}

bool FormProviderClient::IsCallBySelfBundle()
{
    uid_t callingUid = static_cast<uid_t>(IPCSkeleton::GetCallingUid());
    return (getuid() == callingUid);
}
} // namespace AppExecFwk
} // namespace OHOS
