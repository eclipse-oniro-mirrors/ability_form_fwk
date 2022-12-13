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
#include "form_share_mgr.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_event_handler.h"
#include "form_mgr_errors.h"
#include "form_host_interface.h"
#include "form_provider_interface.h"
#include "form_share_connection.h"
#include "form_supply_callback.h"
#include "form_util.h"
#include "in_process_call_wrapper.h"
#include "nlohmann/json.hpp"
#include "string_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t FORM_SHARE_INFO_DELAY_TIMER = 50000;
constexpr int64_t FORM_PACKAGE_FREE_INSTALL_TIMER = 40000;
constexpr const char* ACTION_SHARE_FORM = "action.form.share";
}

FormShareMgr::FormShareMgr()
{
    HILOG_DEBUG("FormShareMgr is created");
};

FormShareMgr::~FormShareMgr()
{
    HILOG_DEBUG("FormShareMgr is destroyed");
    if (eventHandler_ != nullptr) {
        eventHandler_->UnregisterEventTimeoutObserver(shared_from_this());
    }
};

int32_t FormShareMgr::ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
    int64_t requestCode)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form share info get formRecord failed.");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    {
        std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
        requestMap_.emplace(requestCode, callerToken);
    }

    sptr<FormShareConnection> formShareConnection = new (std::nothrow) FormShareConnection(
        formId, formRecord.bundleName, formRecord.abilityName, deviceId, requestCode);
    if (formShareConnection == nullptr) {
        HILOG_ERROR("failed to create formShareConnection.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want want;
    want.SetElementName(formRecord.bundleName, formRecord.abilityName);
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formShareConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed.");
        std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
        requestMap_.erase(requestCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

int32_t FormShareMgr::RecvFormShareInfoFromRemote(const FormShareInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto task = [info]() {
        DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info);
    };
    eventHandler_->PostTask(task);

    return ERR_OK;
}

int32_t FormShareMgr::HandleRecvFormShareInfoFromRemoteTask(const FormShareInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    if (!CheckFormShareInfo(info)) {
        HILOG_ERROR("form share info check failed.");
        return ERR_APPEXECFWK_FORM_SHARE_INFO_CHECK_FAILED;
    }

    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    int32_t userId = FormUtil::GetCurrentAccountId();
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        ACTION_SHARE_FORM, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("get ability info by action failed.");
        return ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST;
    }
    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("form user is not exist.");
        return ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST;
    }

    auto formShareInfoKey = MakeFormShareInfoKey(info);
    {
        std::unique_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        if (shareInfo_.find(formShareInfoKey) != shareInfo_.end()) {
            HILOG_ERROR("form is sharing.");
            return ERR_APPEXECFWK_FORM_SHARING;
        }

        shareInfo_.emplace(formShareInfoKey, info);
    }
    {
        std::unique_lock<std::shared_mutex> guard(eventMapMutex_);
        auto eventId = FormEventHandler::GetEventId();
        eventMap_.emplace(eventId, formShareInfoKey);
        if (eventHandler_ != nullptr) {
            eventHandler_->SendEvent(MSG::FORM_SHARE_INFO_DELAY_MSG, eventId, FORM_SHARE_INFO_DELAY_TIMER);
        }
    }
    auto ret = CheckFormPackage(info, formShareInfoKey);
    if (ret == ERR_APPEXECFWK_FORM_FREE_INSTALLATION) {
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    StartFormUser(info);
    return ERR_OK;
}

int32_t FormShareMgr::CheckFormPackage(const FormShareInfo &info, const std::string &formShareInfoKey)
{
    if (IsExistFormPackage(info.bundleName, info.moduleName)) {
        return ERR_OK;
    }

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator =
        std::make_shared<FormFreeInstallOperator>(formShareInfoKey, eventHandler_);
    auto eventId = FormEventHandler::GetEventId();
    HILOG_DEBUG("free install operator send event, eventId:%{public}" PRId64 ", key: %{public}s",
        eventId, formShareInfoKey.c_str());
    eventHandler_->SendEvent(
        MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG, eventId, FORM_PACKAGE_FREE_INSTALL_TIMER);

    {
        std::unique_lock<std::shared_mutex> guard(freeInstallMapMutex_);
        freeInstallOperatorMap_.emplace(eventId, freeInstallOperator);
    }

    auto ret = freeInstallOperator->StartFreeInstall(info.bundleName, info.moduleName, info.abilityName);
    if (ret != ERR_OK) {
        HILOG_ERROR("free install failed.");
        RemoveFormShareInfo(formShareInfoKey);
        FinishFreeInstallTask(freeInstallOperator);
        return ERR_APPEXECFWK_FORM_FREE_INSTALL_FAILED;
    }
    return ERR_APPEXECFWK_FORM_FREE_INSTALLATION;
}

bool FormShareMgr::CheckFormShareInfo(const FormShareInfo &info)
{
    return !(info.bundleName.empty() ||
            info.moduleName.empty() ||
            info.abilityName.empty() ||
            info.formName.empty() ||
            info.deviceId.empty());
}

std::string FormShareMgr::MakeFormShareInfoKey(const FormShareInfo &info)
{
    return (info.bundleName + info.moduleName + info.abilityName + info.formName);
}

std::string FormShareMgr::MakeFormShareInfoKey(const Want &want)
{
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string moduleName = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    std::string formName = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    return (bundleName + moduleName + abilityName + formName);
}

void FormShareMgr::StartFormUser(const FormShareInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    int32_t userId = FormUtil::GetCurrentAccountId();
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        ACTION_SHARE_FORM, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("get ability info by action failed.");
        return;
    }

    Want want;
    if (!abilityInfo.name.empty()) {
        want.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    } else if (!extensionAbilityInfo.name.empty()) {
        want.SetElementName(extensionAbilityInfo.bundleName, extensionAbilityInfo.name);
    } else {
        HILOG_ERROR("form user is not exist.");
        return;
    }

    want.SetAction(ACTION_SHARE_FORM);
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, info.bundleName);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, info.moduleName);
    want.SetParam(Constants::PARAM_ABILITY_NAME_KEY, info.abilityName);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, info.formName);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, info.formTempFlag);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, info.dimensionId);

    auto errorCode = FormAmsHelper::GetInstance().StartAbility(want, userId);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("start ability failed.");
        RemoveFormShareInfo(MakeFormShareInfoKey(info));
    }
}

bool FormShareMgr::IsExistFormPackage(const std::string &bundleName, const std::string &moduleName)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    BundleInfo bundleInfo;
    auto userId = FormUtil::GetCurrentAccountId();
    if (!FormBmsHelper::GetInstance().GetBundleInfo(bundleName, userId, bundleInfo)) {
        HILOG_ERROR("get bundle info failed");
        return false;
    }

    for (const auto &moduleInfo : bundleInfo.moduleNames) {
        if (moduleInfo.compare(moduleName) == 0) {
            HILOG_DEBUG("module name is exist, moduleName:%{public}s", moduleInfo.c_str());
            return true;
        }
    }

    HILOG_ERROR("module name is not exist, moduleName: %{public}s", moduleName.c_str());
    return false;
}

void FormShareMgr::RemoveFormShareInfo(const std::string &formShareInfoKey)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    {
        std::unique_lock<std::shared_mutex> guard(eventMapMutex_);
        int64_t eventId = 0;
        for (auto iter = eventMap_.begin(); iter != eventMap_.end(); iter++) {
            if (iter->second == formShareInfoKey) {
                eventId = iter->first;
                break;
            }
        }

        if (eventId != 0) {
            eventMap_.erase(eventId);
            if (eventHandler_ != nullptr) {
                eventHandler_->RemoveEvent(MSG::FORM_SHARE_INFO_DELAY_MSG, eventId);
            }
        }
    }

    {
        std::unique_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        shareInfo_.erase(formShareInfoKey);
    }
}

void FormShareMgr::FinishFreeInstallTask(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::unique_lock<std::shared_mutex> guard(freeInstallMapMutex_);

    int64_t eventId = 0;
    for (auto iter = freeInstallOperatorMap_.begin(); iter != freeInstallOperatorMap_.end(); iter++) {
        if (iter->second == freeInstallOperator) {
            eventId = iter->first;
            break;
        }
    }

    if (eventId != 0) {
        freeInstallOperatorMap_.erase(eventId);
        if (eventHandler_ != nullptr) {
            eventHandler_->RemoveEvent(MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG, eventId);
        }
    }
}

void FormShareMgr::OnInstallFinished(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator,
    int32_t resultCode, const std::string &formShareInfoKey)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    FinishFreeInstallTask(freeInstallOperator);

    if (resultCode != ERR_OK) {
        HILOG_ERROR("free install failed.");
        RemoveFormShareInfo(formShareInfoKey);
        return;
    }

    FormShareInfo info;
    {
        std::shared_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        auto it = shareInfo_.find(formShareInfoKey);
        if (it == shareInfo_.end()) {
            HILOG_ERROR("form share info is not found.");
            return;
        }

        it->second.isFreeInstall = true;
        info = it->second;
    }

    StartFormUser(info);
}

void FormShareMgr::HandleFormShareInfoTimeout(int64_t eventId)
{
    HILOG_DEBUG("%{public}s called, eventId:%{public}" PRId64 "", __func__, eventId);

    std::string formShareInfoKey;
    {
        std::unique_lock<std::shared_mutex> guard(eventMapMutex_);
        auto it = eventMap_.find(eventId);
        if (it == eventMap_.end()) {
            HILOG_ERROR("event id is not find.");
            return;
        }
        formShareInfoKey = it->second;
        eventMap_.erase(eventId);
    }
    HILOG_DEBUG("form share info timeout, key: %{public}s", formShareInfoKey.c_str());

    RemoveFormShareInfo(formShareInfoKey);
}

void FormShareMgr::HandleFreeInstallTimeout(int64_t eventId)
{
    HILOG_DEBUG("%{public}s called, eventId:%{public}" PRId64 "", __func__, eventId);
    std::unique_lock<std::shared_mutex> guard(freeInstallMapMutex_);
    freeInstallOperatorMap_.erase(eventId);
}

void FormShareMgr::AddProviderData(const Want &want, WantParams &wantParams)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    auto formShareInfoKey = MakeFormShareInfoKey(want);
    std::string deviceId;
    std::string bundleName;
    std::string moduleName;
    bool isFreeInstall = false;
    std::map<std::string, sptr<IInterface>> providerWantParams;
    {
        std::shared_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        auto it = shareInfo_.find(formShareInfoKey);
        if (it == shareInfo_.end()) {
            HILOG_DEBUG("No shared provider data.");
            return;
        }

        providerWantParams = it->second.providerShareData.GetParams();
        deviceId = it->second.deviceId;
        bundleName = it->second.bundleName;
        moduleName = it->second.moduleName;
        isFreeInstall = it->second.isFreeInstall;
    }

    if (!wantParams.HasParam(Constants::PARAM_DEVICE_ID_KEY)) {
        wantParams.SetParam(Constants::PARAM_DEVICE_ID_KEY, AAFwk::String::Box(deviceId));
    }
    for (auto iter = providerWantParams.begin(); iter != providerWantParams.end(); iter++) {
        wantParams.SetParam(iter->first, iter->second);
    }

    if (isFreeInstall) {
        FormBmsHelper::GetInstance().NotifyModuleNotRemovable(bundleName, moduleName);
        HILOG_INFO("notify module not removable, bundleName: %{public}s, moduleName: %{public}s",
            bundleName.c_str(), moduleName.c_str());
    }

    RemoveFormShareInfo(formShareInfoKey);
}

void FormShareMgr::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_SHARE_REQUEST_CODE, 0));
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);

    if (formProviderProxy == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
        HILOG_ERROR("failed to get formProviderProxy.");
        return;
    }

    int32_t error = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId,
        FormSupplyCallback::GetInstance(), requestCode);
    if (error != ERR_OK) {
        SendResponse(requestCode, error);
        HILOG_ERROR("failed to get acquire provider form info.");
    }

    FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
}

void FormShareMgr::HandleProviderShareData(int64_t formId, const std::string &remoteDeviceId,
    const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form share info get formRecord failed.");
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
        return;
    }

    if (!result) {
        HILOG_ERROR("Failed to parse shared data.");
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
        return;
    }

    FormShareInfo formShareInfo;
    formShareInfo.formId = formRecord.formId;
    formShareInfo.formName = formRecord.formName;
    formShareInfo.bundleName = formRecord.bundleName;
    formShareInfo.moduleName = formRecord.moduleName;
    formShareInfo.abilityName = formRecord.abilityName;
    formShareInfo.formTempFlag = formRecord.formTempFlag;
    formShareInfo.dimensionId = formRecord.specification;
    formShareInfo.providerShareData = wantParams;

    if (formDmsClient_ == nullptr) {
        formDmsClient_ = std::make_shared<FormDistributedClient>();
    }
    int32_t retval = formDmsClient_->ShareForm(remoteDeviceId, formShareInfo);
    if (retval != ERR_OK) {
        HILOG_ERROR("failed to share form from DMS retval = %{public}d.", retval);
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_DISTRIBUTED_SCHEDULE_FAILED);
        return;
    }
    SendResponse(requestCode, ERR_OK);
}

void FormShareMgr::SendResponse(int64_t requestCode, int32_t result)
{
    HILOG_DEBUG("FormMgrService SendResponse called, requestCode:%{public}" PRId64 " result:%{public}d",
        requestCode, result);
    std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
    auto iter = requestMap_.find(requestCode);
    if (iter == requestMap_.end()) {
        HILOG_DEBUG("No form shared request.");
        return;
    }

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(iter->second);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("failed to get form host proxy.");
        return;
    }
    remoteFormHost->OnShareFormResponse(requestCode, result);
    requestMap_.erase(requestCode);
}

bool FormShareMgr::IsShareForm(const Want &want)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    auto formShareInfoKey = MakeFormShareInfoKey(want);
    HILOG_DEBUG("formShareInfoKey: %{public}s", formShareInfoKey.c_str());

    std::shared_lock<std::shared_mutex> guard(shareInfoMapMutex_);
    auto it = shareInfo_.find(formShareInfoKey);
    if (it == shareInfo_.end()) {
        HILOG_DEBUG("This form is not a shared form");
        return false;
    }
    return true;
}

void FormShareMgr::OnEventTimeoutResponse(int64_t msg, int64_t eventId)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    switch (msg) {
        case MSG::FORM_SHARE_INFO_DELAY_MSG: {
            HandleFormShareInfoTimeout(eventId);
            break;
        }
        case MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG: {
            HandleFreeInstallTimeout(eventId);
            break;
        }
        default: {
            break;
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS
