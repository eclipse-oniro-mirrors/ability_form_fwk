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

#ifndef OHOS_FORM_FWK_FORM_RENDER_MGR_INNER_H
#define OHOS_FORM_FWK_FORM_RENDER_MGR_INNER_H

#include <atomic>
#include <queue>
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
 * @class FormRenderMgrInner
 * FormRenderMgrInner provides a facility for managing form render life cycle.
 */
class FormRenderMgrInner {
public:
    FormRenderMgrInner();
    virtual ~FormRenderMgrInner();

    virtual ErrCode RenderForm(
        const FormRecord &formRecord, Want &want, const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode UpdateRenderingForm(FormRecord &formRecord, const FormProviderData &formProviderData,
        const WantParams &wantParams, bool mergeData);

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord,
        const std::string &compId = "", const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode ReloadForm(const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId);

    ErrCode StopRenderingFormCallback(int64_t formId, const Want &want);

    ErrCode AddConnection(int64_t formId, sptr<FormRenderConnection> connection);

    void RemoveConnection(int64_t formId);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj);

    void RerenderAllForms();

    void CleanFormHost(const sptr<IRemoteObject> &host);

    void OnRenderingBlock(const std::string &bundleName);

    ErrCode ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId);

    void PostOnUnlockTask();

    int32_t GetReRenderCount() const;

    sptr<IFormRender> GetRenderRemoteObj() const;

    void SetRenderRemoteObj(sptr<IFormRender> remoteObject);

    ErrCode RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost);

    ErrCode RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams);

private:
    ErrCode ConnectRenderService(const sptr<FormRenderConnection> &connection, int32_t level) const;

    void DisconnectRenderService(const sptr<FormRenderConnection> connection, size_t size) const;

    void AddHostToken(const sptr<IRemoteObject> &host, int64_t formId);

    void RemoveHostToken(const sptr<IRemoteObject> &host);

    void NotifyHostRenderServiceIsDead() const;

    void FillBundleInfo(Want &want, const std::string &bundleName) const;

    void CheckIfFormRecycled(FormRecord &formRecord, Want& want) const;

    ErrCode GetConnectionAndRenderForm(FormRecord &formRecord, Want &want);

private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> &remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

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
#endif // OHOS_FORM_FWK_FORM_RENDER_MGR_INNER_H
