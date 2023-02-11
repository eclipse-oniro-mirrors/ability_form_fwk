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

#ifndef OHOS_FORM_FWK_FORM_RENDER_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_MGR_H

#include <singleton.h>
#include <unordered_map>
#include <unordered_set>

#include "form_record.h"
#include "form_render_connection.h"
#include "form_render_interface.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormRenderService
 * FormRenderService provides a facility for managing form render life cycle.
 */
class FormRenderMgr : public DelayedRefSingleton<FormRenderMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormRenderMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderMgr);

    ErrCode RenderForm(const FormRecord &formRecord, const WantParams &wantParams);

    ErrCode UpdateRenderingForm(int64_t formId, const FormProviderData &formProviderData,
        const WantParams &wantParams, bool mergeData);

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord);

    ErrCode RenderFormCallback(int64_t formId, const Want &want);

    ErrCode StopRenderingFormCallback(int64_t formId, const Want &want);

    ErrCode AddConnection(int64_t formId, sptr<FormAbilityConnection> connection);

    ErrCode RemoveConnection(int64_t formId);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj);

    bool IsNeedRender(int64_t formId);

    void ReconnectRenderService();

    void RerenderAll();
private:
    bool IsRemoveConnection(int64_t formId);

    ErrCode ConnectRenderService(const sptr<AAFwk::IAbilityConnection> &connection) const;

    void AddHostToken(int64_t formId);

    void RemoveHostToken(const sptr<IRemoteObject> &host);

    void NotifyHostConnectRenderFailed() const;

    void SecondFormRenderConnect(const FormRecord &formRecord, const WantParams &wantParams,
        const sptr<IRemoteObject> &remoteObject, int32_t connectId);

private:
    // <FormRenderConnection, FormStopRenderingConnection>
    using RenderConnectionPair = std::pair<sptr<FormAbilityConnection>, sptr<FormAbilityConnection>>;
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

    int32_t maxConnectKey = 0;
    mutable std::mutex conMutex_;
    std::unordered_map<int64_t, RenderConnectionPair> renderFormConnections_;
    sptr<IFormRender> renderRemoteObj_;
    sptr<FormRenderConnection> reconnectRenderConnection_;
    sptr<IRemoteObject::DeathRecipient> renderDeathRecipient_;
    mutable std::mutex hostsMutex_;
    std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> etsHosts_;
    int32_t reconnectCount_ = 0;
};

/**
 * @class FormRenderRecipient
 * FormRenderRecipient notices IRemoteBroker died.
 */
class FormRenderRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void()>;

    explicit FormRenderRecipient(RemoteDiedHandler handler);

    virtual ~FormRenderRecipient();

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    RemoteDiedHandler handler_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_MGR_H
