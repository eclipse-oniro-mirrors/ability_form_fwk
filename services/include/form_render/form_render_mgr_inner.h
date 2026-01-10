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
#include <shared_mutex>
#include <unordered_map>

#include "want.h"

#include "data_center/form_record/form_record.h"
#include "form_render/form_render_connection.h"
#include "form_render/form_res_sched.h"
#include "form_render_interface.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormRenderMgrInner
 * FormRenderMgrInner provides a facility for managing form render life cycle.
 */
class FormRenderMgrInner : public std::enable_shared_from_this<FormRenderMgrInner> {
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

    ErrCode checkConnectionsFormIds(std::vector<int64_t> formIds, std::vector<int64_t> &needconFormIds);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj);

    void RerenderAllForms();

    void CleanFormHost(const sptr<IRemoteObject> &host);

    void RemoveHostToken(const sptr<IRemoteObject> &host);

    void OnRenderingBlock(const std::string &bundleName);

    ErrCode ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId);

    void PostOnUnlockTask();

    void NotifyScreenOn();

    void PostSetRenderGroupEnableFlagTask(int64_t formId, bool isEnable);

    void PostSetVisibleChangeTask(int64_t formId, bool isVisible);

    int32_t GetReRenderCount() const;

    sptr<IFormRender> GetRenderRemoteObj() const;

    void SetRenderRemoteObj(sptr<IFormRender> remoteObject);

    ErrCode RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost);

    ErrCode RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams);

    ErrCode UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
        float formViewScale);

    void SetUserId(int32_t userId);

    int32_t GetUserId() const;

    void RerenderAllFormsImmediate();

    void DisconnectAllRenderConnections();

    bool GetIsFRSDiedInLowMemory();

    void PostSetRenderGroupParamsTask(const int64_t formId, const Want &want);

private:
    ErrCode ConnectRenderService(const sptr<FormRenderConnection> &connection, int32_t level) const;

    void DisconnectRenderService(const sptr<FormRenderConnection> connection, size_t size) const;

    void AddHostToken(const sptr<IRemoteObject> &host, int64_t formId);

    void NotifyHostRenderServiceIsDead() const;

    void FillBundleInfo(Want &want, const std::string &bundleName) const;

    void CheckIfFormRecycled(FormRecord &formRecord, Want& want) const;

    ErrCode GetConnectionAndRenderForm(FormRecord &formRecord, Want &want);

    ErrCode GetRenderObject(sptr<IRemoteObject> &renderObj);

    bool GetRenderFormConnectId(const int64_t formId, int32_t& connectId);

    bool GetRenderFormConnection(sptr<FormRenderConnection> &connection, const int64_t formId);

    void GetConnectedForms(const std::vector<int64_t> &formIds, std::vector<int64_t> &connectedForms);

    ErrCode RenderConnectedForm(const FormRecord &formRecord, Want &want, const sptr<FormRenderConnection> &connection);

    ErrCode PostStopRenderingFormTask(const FormRecord &formRecord, Want &want);

    ErrCode CheckRenderConnectionExistById(int64_t formId);

    /**
     * Recovers the Form Render Service (FRS) process when a form event.
     *
     * This function is triggered to revive the FRS process under the following conditions:
     * 1. A form event (e.g., RenderForm, RecoverForms) occurs.
     * 2. The FRS process was previously terminated by the system's low-memory killer.
     */
    void RecoverFRSOnFormActivity();

private:
    class RemoteObjHash {
    public:
        size_t operator() (const sptr<IRemoteObject> &remoteObj) const
        {
            return reinterpret_cast<size_t>(remoteObj.GetRefPtr());
        }
    };

    mutable std::mutex resourceMutex_;
    mutable std::shared_mutex renderRemoteObjMutex_;
    mutable std::mutex formResSchedMutex_;
    // <formId, connectionToRenderService>
    std::unordered_map<int64_t, sptr<FormRenderConnection>> renderFormConnections_;
    // <hostToken, formIds>
    std::unordered_map<sptr<IRemoteObject>, std::unordered_set<int64_t>, RemoteObjHash> etsHosts_;
    sptr<IFormRender> renderRemoteObj_ = nullptr;
    std::unique_ptr<FormResSched> formResSched_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> renderDeathRecipient_ = nullptr;
    std::atomic<int32_t> atomicRerenderCount_ = 0;
    // userId_ is Active User
    bool isActiveUser_ = true;
    int32_t userId_ = 0;
    std::atomic_bool isFrsDiedInLowMemory_ = false;
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
