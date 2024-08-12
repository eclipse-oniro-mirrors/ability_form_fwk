/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "fms_log_wrapper.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "provider_connect_proxy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 * @param element service ability's ElementName.
 * @param remoteObject the session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void ProviderConnectProxy::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_DEBUG("abilityName:%{public}s,resultCode:%{public}d",
        element.GetAbilityName().c_str(), resultCode);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }

    if (!data.WriteParcelable(&element)) {
        HILOG_ERROR("fail write element");
        return;
    }

    if (remoteObject) {
        if (!data.WriteBool(true) || !data.WriteRemoteObject(remoteObject)) {
            HILOG_ERROR("fail write flag and remote object");
            return;
        }
    } else {
        if (!data.WriteBool(false)) {
            HILOG_ERROR("fail write flag");
            return;
        }
    }

    if (!data.WriteInt32(resultCode)) {
        HILOG_ERROR("fail write resultCode");
        return;
    }

    if (!SendTransactCmd(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option)) {
        HILOG_ERROR("fail SendRequest");
        return;
    }
}
/**
 * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
 * @param element service ability's ElementName.
 * @param resultCode ERR_OK on success, others on failure.
 */
void ProviderConnectProxy::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_DEBUG(
        "element:%{public}s, resultCode:%{public}d", element.GetURI().c_str(), resultCode);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    if (!WriteInterfaceToken(data)) {
        HILOG_ERROR("write interface token failed");
        return;
    }
    if (!data.WriteParcelable(&element)) {
        HILOG_ERROR("fail write element");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        HILOG_ERROR("fail write resultCode");
        return;
    }

    if (!SendTransactCmd(IAbilityConnection::ON_ABILITY_DISCONNECT_DONE, data, reply, option)) {
        HILOG_ERROR("fail SendRequest");
        return;
    }
}

bool ProviderConnectProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(ProviderConnectProxy::GetDescriptor())) {
        HILOG_ERROR("write interface token failed");
        return false;
    }
    return true;
}

bool ProviderConnectProxy::SendTransactCmd(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    sptr<IRemoteObject> remote = Remote();
    if (!remote) {
        HILOG_ERROR("get remoteObject failed,cmd:%{public}d", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        HILOG_ERROR("SendRequest failed:%{public}d,cmd:%{public}d", result, code);
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
