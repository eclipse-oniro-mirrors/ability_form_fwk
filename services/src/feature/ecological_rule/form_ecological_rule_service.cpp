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

#include <cinttypes>
#include <chrono>

#include "feature/ecological_rule/form_ecological_rule_service.h"
#include "fms_log_wrapper.h"
#include "iremote_broker.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
using namespace std::chrono;
static inline const std::u16string ERMS_INTERFACE_TOKEN =
    u"ohos.cloud.ecologicalrulemgrservice.IEcologicalRuleMgrService";
std::mutex FormEcologicalRuleClient::instanceLock_;
sptr<IFormEcologicalRule> FormEcologicalRuleClient::ecologicalRuleMgrServiceProxy_;
sptr<IRemoteObject::DeathRecipient> FormEcologicalRuleClient::deathRecipient_;

FormEcologicalRuleClient::FormEcologicalRuleClient()
{}

FormEcologicalRuleClient::~FormEcologicalRuleClient()
{
    if (ecologicalRuleMgrServiceProxy_ != nullptr) {
        auto remoteObj = ecologicalRuleMgrServiceProxy_->AsObject();
        if (remoteObj != nullptr) {
            remoteObj->RemoveDeathRecipient(deathRecipient_);
        }
    }
}
inline int64_t GetCurrentTimeMicro()
{
    return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

sptr<IFormEcologicalRule> FormEcologicalRuleClient::ConnectService()
{
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        HILOG_ERROR("GetSystemAbilityManager error");
        return nullptr;
    }

    auto systemAbility = samgr->CheckSystemAbility(ECOLOGICAL_RULE_MANAGER_SA_ID);
    if (systemAbility == nullptr) {
        HILOG_ERROR("CheckSystemAbility error, ECOLOGICAL_RULE_MANAGER_SA_ID = 6105");
        return nullptr;
    }

    deathRecipient_ = new (std::nothrow) FormEcologicalRuleDeathRecipient();
    systemAbility->AddDeathRecipient(deathRecipient_);

    sptr<IFormEcologicalRule> it = iface_cast<IFormEcologicalRule>(systemAbility);
    if (it == nullptr) {
        HILOG_ERROR("IFormEcologicalRule cast failed");
        it = new FormEcologicalRuleProxy(systemAbility);
    }

    return it;
}

bool FormEcologicalRuleClient::CheckConnectService()
{
    std::lock_guard<std::mutex> lock(instanceLock_);
    if (ecologicalRuleMgrServiceProxy_ == nullptr) {
        HILOG_DEBUG("redo ConnectService");
        ecologicalRuleMgrServiceProxy_ = ConnectService();
    }
    if (ecologicalRuleMgrServiceProxy_ == nullptr) {
        HILOG_ERROR("Connect SA Failed");
        return false;
    }
    return true;
}

void FormEcologicalRuleClient::OnRemoteSaDied(const wptr<IRemoteObject> &object)
{
    std::lock_guard<std::mutex> lock(instanceLock_);
    ecologicalRuleMgrServiceProxy_ = ConnectService();
}

int32_t FormEcologicalRuleClient::IsSupportPublishForm(const std::vector<OHOS::AAFwk::Want> &wants,
    const CallerInfo &callerInfo, bool &bSupport)
{
    HILOG_DEBUG("callerInfo = %{public}s", callerInfo.ToString().c_str());
    if (callerInfo.packageName.find_first_not_of(' ') == std::string::npos) {
        bSupport = true;
        HILOG_DEBUG("empty callerInfoPackageName,bSupport=true");
        return 0;
    }
    if (!CheckConnectService()) {
        return -1;
    }
    int32_t res = ecologicalRuleMgrServiceProxy_->IsSupportPublishForm(wants, callerInfo, bSupport);
    HILOG_DEBUG("IsSupportPublishForm end, bSupport = %{public}d", bSupport);
    return res;
}

void FormEcologicalRuleDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    FormEcologicalRuleClient::GetInstance().OnRemoteSaDied(object);
}

int32_t FormEcologicalRuleProxy::IsSupportPublishForm(const std::vector<Want> &wants,
    const CallerInfo &callerInfo, bool &bSupport)
{
    HILOG_DEBUG("call");
    MessageParcel data;
    if (!data.WriteInterfaceToken(ERMS_INTERFACE_TOKEN)) {
        HILOG_ERROR("write token failed");
        return ERR_FAILED;
    }
    if (!data.WriteInt32(wants.size())) {
        HILOG_ERROR("write wants size failed");
        return ERR_FAILED;
    }
    for (auto &want : wants) {
        if (!data.WriteParcelable(&want)) {
            HILOG_ERROR("write want failed");
            return ERR_FAILED;
        }
    }
    if (!data.WriteParcelable(&callerInfo)) {
        HILOG_ERROR("write callerInfo failed");
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
    int32_t ret = remote->SendRequest(IS_SUPPORT_PUBLISH_FORM_CMD, data, reply, option);
    IPCSkeleton::SetCallingIdentity(originId);
    if (ret != ERR_NONE) {
        HILOG_ERROR("SendRequest error, ret = %{public}d", ret);
        return ERR_FAILED;
    }
    bSupport = reply.ReadBool();
    HILOG_INFO("end, bSupport=%{public}d", bSupport);
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
