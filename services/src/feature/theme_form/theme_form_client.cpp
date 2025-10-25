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

#ifdef THEME_MGR_ENABLE

#include "feature/theme_form/theme_form_client.h"

#include <cinttypes>
#include <unordered_set>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "iremote_proxy.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t TIME_OUT = 3;
constexpr int32_t MAX_TIMES = 10;
constexpr int32_t DELAY_TIME = 300000;
constexpr int32_t THEME_MANAGER_SERVICE_ID = 0x00010136;
constexpr ErrCode ERR_FAILED = -1;
static const std::unordered_set<int32_t> errorCodeList = {
    NO_ERROR, NO_PERMISSION, NOT_SYSTEM_APP, IPC_FAILED, THEME_NULLPTR, FILE_EXCEPTION,
    PACKAGE_OVERSIZED, IS_ACTIVATING, PACKAGE_FORMAT_ERROR, SA_UNLOADING, DATABASE_ERROR,
    INVALID_VALUE, INTERNAL_ERROR, DELETE_FAILED
};

ThemeFormClient::ThemeFormClient()
{
}

ThemeFormClient::~ThemeFormClient()
{
    CleanResource();
}

void ThemeFormClient::CleanResource()
{
    std::lock_guard<std::mutex> lock(themeSvcProxyMutex_);
    if (themeSvcProxy_ != nullptr && deathRecipient_ != nullptr) {
        auto remoteObj = themeSvcProxy_->AsObject();
        if (remoteObj != nullptr) {
            remoteObj->RemoveDeathRecipient(deathRecipient_);
        }
        deathRecipient_ = nullptr;
    }
    themeSvcProxy_ = nullptr;
}

int32_t ThemeFormClient::AddForm(const FormNotifyInfo& info)
{
    auto proxy = GetProxy();
    if (!proxy) {
        HILOG_ERROR("GetProxy failed!");
        return THEME_NULLPTR;
    }

    ThemeManagerThemeFormInfoByParcel parcel;
    CreateThemeFormParcel(info, parcel);

    int32_t result = 0;
    for (int i = 0; i <= MAX_TIMES; i++) {
        result = ConvertIntToErrorCode(proxy->AddForm(parcel));
        if (result == static_cast<int32_t>(NO_ERROR)) {
            HILOG_INFO("AddForm : SA was unloaded.");
            break;
        }
        HILOG_WARN("AddForm : UnloadSelf saManager is fail, code:%{public}d, times:%{public}d", result, i);
        usleep(DELAY_TIME);
    }

    HILOG_WARN("AddForm : code:%{public}d", result);
    return result;
}

int32_t ThemeFormClient::DeleteForms(const vector<int64_t> &formIds)
{
    auto proxy = GetProxy();
    if (!proxy) {
        HILOG_ERROR("GetProxy failed!");
        return THEME_NULLPTR;
    }

    int32_t result = 0;
    for (int i = 0; i <= MAX_TIMES; i++) {
        result = ConvertIntToErrorCode(proxy->DeleteForm(formIds));
        if (result == static_cast<int32_t>(NO_ERROR)) {
            HILOG_INFO("DeleteForm : SA was unloaded");
            break;
        }
        HILOG_WARN("DeleteForm : UnloadSelf saManager is fail, code:%{public}d, times:%{public}d", result, i);
        usleep(DELAY_TIME);
    }

    return result;
}

void ThemeFormClient::CreateThemeFormParcel(const FormNotifyInfo& info, ThemeManagerThemeFormInfoByParcel& parcel)
{
    auto& themeFormInfo = parcel.themeFormInfo_;
    themeFormInfo.formId = info.formId;
    auto& want = info.want;
    themeFormInfo.themeFormDimension =
        static_cast<ThemeFormDimension>(want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0));
    themeFormInfo.themeFormLocation =
        static_cast<ThemeFormLocation>(want.GetIntParam(Constants::FORM_LOCATION_KEY, 0));
    themeFormInfo.themeFormId = want.GetStringParam(Constants::PARAM_THEME_THEME_FORM_ID);
    themeFormInfo.themeId = want.GetStringParam(Constants::PARAM_THEME_THEME_ID);

    HILOG_INFO("get theme form info, themeFormId:%{public}s, themeId:%{public}s",
        themeFormInfo.themeFormId.c_str(), themeFormInfo.themeId.c_str());
}

ErrorCode ThemeFormClient::ConvertIntToErrorCode(int32_t errorCode)
{
    ErrorCode themeErrorCode = E_UNKNOWN;
    auto it = errorCodeList.find(errorCode);
    if (it != errorCodeList.end()) {
        themeErrorCode = static_cast<ErrorCode>(errorCode);
    }
    return themeErrorCode;
}

void ThemeFormClient::OnRemoteSaDied(const wptr<IRemoteObject> &object)
{
    CleanResource();
}

sptr<IThemeManagerService> ThemeFormClient::GetProxy()
{
    std::lock_guard<std::mutex> lock(themeSvcProxyMutex_);
    if (themeSvcProxy_) {
        return themeSvcProxy_;
    }

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOG_ERROR("Get samgr failed!");
        return nullptr;
    }

    sptr<IRemoteObject> object = samgr->CheckSystemAbility(THEME_MANAGER_SERVICE_ID);
    if (object == nullptr) {
        object = samgr->LoadSystemAbility(THEME_MANAGER_SERVICE_ID, TIME_OUT);
    }

    if (object != nullptr) {
        deathRecipient_ = new (std::nothrow) ThemeFormDeathRecipient();
        if (deathRecipient_ == nullptr) {
            HILOG_ERROR("Create ThemeFormDeathRecipient failed!");
            return nullptr;
        }
        object->AddDeathRecipient(deathRecipient_);
        sptr<IThemeManagerService> proxy = iface_cast<IThemeManagerService>(object);
        if (proxy == nullptr) {
            HILOG_INFO("iface_cast failed!");
            proxy = new ThemeFormServiceProxy(object);
        }
        themeSvcProxy_ = proxy;
    }

    return themeSvcProxy_;
}

void ThemeFormDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    ThemeFormClient::GetInstance().OnRemoteSaDied(object);
}

ErrCode ThemeFormServiceProxy::AddForm(const ThemeManagerThemeFormInfoByParcel& themeFormInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOG_ERROR("write token failed");
        return ERR_FAILED;
    }

    if (!data.WriteParcelable(&themeFormInfo)) {
        HILOG_ERROR("write themeFormInfo failed");
        return ERR_FAILED;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    MessageParcel reply;
    auto remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("get Remote failed");
        return ERR_FAILED;
    }

    std::string originId = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(IThemeManagerServiceIpcCode::COMMAND_ADD_FORM), data, reply, option);
    IPCSkeleton::SetCallingIdentity(originId);
    if (ret != ERR_NONE) {
        HILOG_ERROR("SendRequest error, ret = %{public}d", ret);
        return ERR_FAILED;
    }

    return ERR_OK;
}

ErrCode ThemeFormServiceProxy::DeleteForm(const vector<long> &formIds)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOG_ERROR("write token failed");
        return ERR_FAILED;
    }

    if (!data.WriteInt64Vector(formIds)) {
        HILOG_ERROR("write formIds failed");
        return ERR_FAILED;
    }

    MessageOption option = { MessageOption::TF_SYNC };
    MessageParcel reply;
    auto remote = Remote();
    if (remote == nullptr) {
        HILOG_ERROR("get Remote failed");
        return ERR_FAILED;
    }
    std::string originId = IPCSkeleton::ResetCallingIdentity();
    int32_t ret = remote->SendRequest(
        static_cast<uint32_t>(IThemeManagerServiceIpcCode::COMMAND_DELETE_FORM), data, reply, option);
    IPCSkeleton::SetCallingIdentity(originId);
    if (ret != ERR_NONE) {
        HILOG_ERROR("SendRequest error, ret = %{public}d", ret);
        return ERR_FAILED;
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
#endif // THEME_MGR_ENABLE
