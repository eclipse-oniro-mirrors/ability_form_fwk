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

#include <atomic>
#include <singleton.h>
#include <unordered_map>

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

    ErrCode RenderForm(
        const FormRecord &formRecord, const WantParams &wantParams, const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode UpdateRenderingForm(int64_t formId, const FormProviderData &formProviderData,
        const WantParams &wantParams, bool mergeData);

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord, const std::string &compId = "", const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode ReloadForm(std::vector<int64_t> &&formIds, const std::string &bundleName, int32_t userId);

    ErrCode RenderFormCallback(int64_t formId, const Want &want);

    ErrCode StopRenderingFormCallback(int64_t formId, const Want &want);

    ErrCode AddConnection(int64_t formId, sptr<FormRenderConnection> connection);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj);

    bool IsNeedRender(int64_t formId);

    void RerenderAllForms();

    void CleanFormHost(const sptr<IRemoteObject> &host);

    void HandleConnectFailed(int64_t formId, int32_t errorCode) const;

    bool IsRerenderForRenderServiceDied(int64_t formId);

private:
    ErrCode ConnectRenderService(const sptr<FormRenderConnection> &connection) const;

    void DisconnectRenderService(const sptr<FormRenderConnection> connection, size_t size) const;

    void AddHostToken(const sptr<IRemoteObject> &host, int64_t formId);

    void RemoveHostToken(const sptr<IRemoteObject> &host);

    void NotifyHostRenderServiceIsDead() const;

private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> &remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

    int32_t maxConnectKey = 0;
    mutable std::mutex resourceMutex_;
    // <formId, connectionToRenderService>
    std::unordered_map<int64_t, sptr<FormRenderConnection>> renderFormConnections_;
    // <hostToken, formIds>
    std::unordered_map<sptr<IRemoteObject>, std::unordered_set<int64_t>, RemoteObjHash> etsHosts_;
    sptr<IFormRender> renderRemoteObj_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> renderDeathRecipient_ = nullptr;
    std::atomic<int32_t> atomicRerenderCount_ = 0;
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
