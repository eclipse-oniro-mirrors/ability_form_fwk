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
#include "feature/form_share/form_share_mgr.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "common/event/form_event_handler.h"
#include "form_mgr_errors.h"
#include "form_host_interface.h"
#include "form_provider_interface.h"
#include "common/util/form_serial_queue.h"
#include "feature/form_share/form_share_connection.h"
#include "form_provider/form_supply_callback.h"
#include "common/util/form_util.h"
#include "in_process_call_wrapper.h"
#include "nlohmann/json.hpp"
#include "string_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t FORM_SHARE_INFO_DELAY_TIMER = 50000;
constexpr int64_t FORM_PACKAGE_FREE_INSTALL_TIMER = 40000;
constexpr int64_t FORM_SHARE_INFO_MAX_SIZE = 32;
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
    HILOG_DEBUG("call");
    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form share info get formRecord failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    {
        std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
        requestMap_.emplace(requestCode, callerToken);
    }

    sptr<FormShareConnection> formShareConnection = new (std::nothrow) FormShareConnection(
        formId, formRecord.bundleName, formRecord.abilityName, deviceId, requestCode, formRecord.providerUserId);
    if (formShareConnection == nullptr) {
        HILOG_ERROR("create formShareConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    Want want;
    want.SetElementName(formRecord.bundleName, formRecord.abilityName);
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formShareConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
        requestMap_.erase(requestCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

int32_t FormShareMgr::RecvFormShareInfoFromRemote(const FormShareInfo &info, const int32_t userId)
{
    HILOG_DEBUG("call");

    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto task = [info, userId]() {
        DelayedSingleton<FormShareMgr>::GetInstance()->HandleRecvFormShareInfoFromRemoteTask(info, userId);
    };
    serialQueue_->ScheduleTask(0, task);

    return ERR_OK;
}

int32_t FormShareMgr::HandleRecvFormShareInfoFromRemoteTask(const FormShareInfo &info, const int32_t userId)
{
    HILOG_DEBUG("call");

    if (!CheckFormShareInfo(info)) {
        HILOG_ERROR("form share info check failed");
        return ERR_APPEXECFWK_FORM_SHARE_INFO_CHECK_FAILED;
    }

    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        ACTION_SHARE_FORM, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("get ability info by action failed");
        return ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST;
    }
    if (abilityInfo.name.empty() && extensionAbilityInfo.name.empty()) {
        HILOG_ERROR("formUser not exist");
        return ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST;
    }

    auto formShareInfoKey = MakeFormShareInfoKey(info);
    {
        std::unique_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        if (shareInfo_.find(formShareInfoKey) != shareInfo_.end()) {
            HILOG_ERROR("form is sharing");
            return ERR_APPEXECFWK_FORM_SHARING;
        }
        if (shareInfo_.size() > FORM_SHARE_INFO_MAX_SIZE) {
            HILOG_ERROR("The maximum number of shared cards has been reached");
            return ERR_APPEXECFWK_FORM_SHARING_MAX_SIZE;
        }

        shareInfo_.emplace(formShareInfoKey, info);
    }
    {
        std::unique_lock<std::shared_mutex> guard(eventMapMutex_);
        auto eventId = FormEventHandler::GetEventId();
        eventMap_.emplace(eventId, formShareInfoKey);
        if (eventHandler_ != nullptr) {
            eventHandler_->ProcessEvent(MSG::FORM_SHARE_INFO_DELAY_MSG, eventId, FORM_SHARE_INFO_DELAY_TIMER);
        }
    }
    auto ret = CheckFormPackage(info, formShareInfoKey, userId);
    if (ret == ERR_APPEXECFWK_FORM_FREE_INSTALLATION) {
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    StartFormUser(info, userId);
    return ERR_OK;
}

int32_t FormShareMgr::CheckFormPackage(const FormShareInfo &info, const std::string &formShareInfoKey,
    const int32_t userId)
{
    if (IsExistFormPackage(info.bundleName, info.moduleName, userId)) {
        return ERR_OK;
    }

    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("null eventHandler_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator =
        std::make_shared<FormFreeInstallOperator>(formShareInfoKey, serialQueue_);
    auto eventId = FormEventHandler::GetEventId();
    HILOG_DEBUG("free install operator send event, eventId:%{public}" PRId64 ", key:%{public}s",
        eventId, formShareInfoKey.c_str());
    eventHandler_->ProcessEvent(
        MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG, eventId, FORM_PACKAGE_FREE_INSTALL_TIMER);

    {
        std::unique_lock<std::shared_mutex> guard(freeInstallMapMutex_);
        freeInstallOperatorMap_.emplace(eventId, freeInstallOperator);
    }

    auto ret = freeInstallOperator->StartFreeInstall(info.bundleName, info.moduleName, info.abilityName, userId);
    if (ret != ERR_OK) {
        HILOG_ERROR("free install failed");
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

void FormShareMgr::StartFormUser(const FormShareInfo &info, const int32_t userId)
{
    HILOG_DEBUG("call");
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    if (!FormBmsHelper::GetInstance().GetAbilityInfoByAction(
        ACTION_SHARE_FORM, userId, abilityInfo, extensionAbilityInfo)) {
        HILOG_ERROR("get ability info by action failed");
        return;
    }

    Want want;
    if (!abilityInfo.name.empty()) {
        want.SetElementName(abilityInfo.bundleName, abilityInfo.name);
    } else if (!extensionAbilityInfo.name.empty()) {
        want.SetElementName(extensionAbilityInfo.bundleName, extensionAbilityInfo.name);
    } else {
        HILOG_ERROR("formUser not exist");
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
        HILOG_ERROR("start ability failed");
        RemoveFormShareInfo(MakeFormShareInfoKey(info));
    }
}

bool FormShareMgr::IsExistFormPackage(const std::string &bundleName, const std::string &moduleName,
    const int32_t userId)
{
    HILOG_DEBUG("call");
    BundleInfo bundleInfo;
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

    HILOG_ERROR("moduleName:%{public}s not exist", moduleName.c_str());
    return false;
}

void FormShareMgr::RemoveFormShareInfo(const std::string &formShareInfoKey)
{
    HILOG_DEBUG("call");
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
            if (serialQueue_ != nullptr) {
                serialQueue_->CancelDelayTask(std::make_pair(MSG::FORM_SHARE_INFO_DELAY_MSG, eventId));
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
    HILOG_DEBUG("call");
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
        if (serialQueue_ != nullptr) {
            serialQueue_->CancelDelayTask(std::make_pair(MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG, eventId));
        }
    }
}

void FormShareMgr::OnInstallFinished(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator,
    int32_t resultCode, const std::string &formShareInfoKey, const int32_t userId)
{
    HILOG_DEBUG("call");

    FinishFreeInstallTask(freeInstallOperator);

    if (resultCode != ERR_OK) {
        HILOG_ERROR("free install failed");
        RemoveFormShareInfo(formShareInfoKey);
        return;
    }

    FormShareInfo info;
    {
        std::shared_lock<std::shared_mutex> guard(shareInfoMapMutex_);
        auto it = shareInfo_.find(formShareInfoKey);
        if (it == shareInfo_.end()) {
            HILOG_ERROR("invalid formShareInfo");
            return;
        }

        it->second.isFreeInstall = true;
        info = it->second;
    }

    StartFormUser(info, userId);
}

void FormShareMgr::HandleFormShareInfoTimeout(int64_t eventId)
{
    HILOG_DEBUG("eventId:%{public}" PRId64 "", eventId);

    std::string formShareInfoKey;
    {
        std::unique_lock<std::shared_mutex> guard(eventMapMutex_);
        auto it = eventMap_.find(eventId);
        if (it == eventMap_.end()) {
            HILOG_ERROR("eventId not find");
            return;
        }
        formShareInfoKey = it->second;
        eventMap_.erase(eventId);
    }
    HILOG_DEBUG("form share info timeout, key:%{public}s", formShareInfoKey.c_str());

    RemoveFormShareInfo(formShareInfoKey);
}

void FormShareMgr::HandleFreeInstallTimeout(int64_t eventId)
{
    HILOG_DEBUG("eventId:%{public}" PRId64 "", eventId);
    std::unique_lock<std::shared_mutex> guard(freeInstallMapMutex_);
    freeInstallOperatorMap_.erase(eventId);
}

void FormShareMgr::AddProviderData(const Want &want, WantParams &wantParams)
{
    HILOG_DEBUG("call");

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
            HILOG_DEBUG("No sharedProviderData");
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
        HILOG_INFO("notify module not removable, bundleName:%{public}s, moduleName:%{public}s",
            bundleName.c_str(), moduleName.c_str());
    }

    RemoveFormShareInfo(formShareInfoKey);
}

void FormShareMgr::AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
    const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    HILOG_DEBUG("call");
    int64_t requestCode = static_cast<int64_t>(want.GetLongParam(Constants::FORM_SHARE_REQUEST_CODE, 0));
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    sptr<IFormProvider> formProviderProxy = iface_cast<IFormProvider>(remoteObject);

    if (formProviderProxy == nullptr) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_COMMON_CODE);
        HILOG_ERROR("get formProviderProxy failed");
        return;
    }

    int32_t error = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId,
        FormSupplyCallback::GetInstance(), requestCode);
    if (error != ERR_OK) {
        SendResponse(requestCode, error);
        HILOG_ERROR("acquire providerFormInfo failed");
    }

    FormSupplyCallback::GetInstance()->RemoveConnection(connectId);
}

void FormShareMgr::HandleProviderShareData(int64_t formId, const std::string &remoteDeviceId,
    const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result)
{
    HILOG_DEBUG("call");

    FormRecord formRecord;
    bool isFormRecExist = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isFormRecExist) {
        HILOG_ERROR("form share info get formRecord failed");
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
        return;
    }

    if (!result) {
        HILOG_ERROR("fail parse shared data");
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
        formDmsClient_ = std::make_unique<FormDistributedClient>();
    }
    int32_t retval = formDmsClient_->ShareForm(remoteDeviceId, formShareInfo);
    if (retval != ERR_OK) {
        HILOG_ERROR("fail share form from DMS retval = %{public}d", retval);
        SendResponse(requestCode, ERR_APPEXECFWK_FORM_DISTRIBUTED_SCHEDULE_FAILED);
        return;
    }
    SendResponse(requestCode, ERR_OK);
}

void FormShareMgr::SendResponse(int64_t requestCode, int32_t result)
{
    HILOG_DEBUG("FormMgrService SendResponse call, requestCode:%{public}" PRId64 " result:%{public}d",
        requestCode, result);
    std::unique_lock<std::shared_mutex> guard(requestMapMutex_);
    auto iter = requestMap_.find(requestCode);
    if (iter == requestMap_.end()) {
        HILOG_DEBUG("No form shared request");
        return;
    }

    sptr<IFormHost> remoteFormHost = iface_cast<IFormHost>(iter->second);
    if (remoteFormHost == nullptr) {
        HILOG_ERROR("get formHostProxy failed");
        return;
    }
    remoteFormHost->OnShareFormResponse(requestCode, result);
    requestMap_.erase(requestCode);
}

bool FormShareMgr::IsShareForm(const Want &want)
{
    HILOG_DEBUG("call");
    auto formShareInfoKey = MakeFormShareInfoKey(want);
    HILOG_DEBUG("formShareInfoKey:%{public}s", formShareInfoKey.c_str());

    std::shared_lock<std::shared_mutex> guard(shareInfoMapMutex_);
    auto it = shareInfo_.find(formShareInfoKey);
    if (it == shareInfo_.end()) {
        HILOG_DEBUG("The form not sharedForm");
        return false;
    }
    return true;
}

void FormShareMgr::OnEventTimeoutResponse(int64_t msg, int64_t eventId)
{
    HILOG_DEBUG("call");
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
