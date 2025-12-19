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
#include <queue>
#include <singleton.h>

#include "data_center/form_record/form_record.h"
#include "form_render/form_render_connection.h"
#include "form_render_interface.h"
#include "form_render/form_render_mgr_inner.h"
#include "form_render/form_sandbox_render_mgr_inner.h"
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

    void OnScreenUnlock(int32_t userId);

    void OnUnlock(int32_t userId);

    void NotifyScreenOn();

    void SetRenderGroupEnableFlag(int64_t formId, bool isEnable);

    void SetVisibleChange(int64_t formId, bool isVisible, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord,
        const std::string &compId = "", const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode ReloadForm(const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId);

    ErrCode RenderFormCallback(int64_t formId, const Want &want);

    ErrCode StopRenderingFormCallback(int64_t formId, const Want &want);

    void GetFormRenderState();

    bool GetIsSecondMounted() const;

    ErrCode AddConnection(int64_t formId, sptr<FormRenderConnection> connection, const FormRecord &formRecord);

    void RemoveConnection(int64_t formId, const FormRecord &formRecord);

    ErrCode checkConnectionsFormIds(std::vector<int64_t> formIds, int32_t userId, std::vector<int64_t> &needconFormIds);

    void reAddConnections(std::vector<int64_t> formIds, int32_t userId, const sptr<IRemoteObject> &remoteObject);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj, const FormRecord &formRecord);

    bool IsNeedRender(int64_t formId);

    void CleanFormHost(const sptr<IRemoteObject> &host, const int hostCallingUid);

    void RemoveHostToken(const sptr<IRemoteObject> &host, const int hostCallingUid);

    void HandleConnectFailed(int64_t formId, int32_t errorCode) const;

    bool IsRerenderForRenderServiceDied(int64_t formId);

    void OnRenderingBlock(const std::string &bundleName);

    ErrCode ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId);

    void AddAcquireProviderFormInfoTask(int32_t userId, std::function<void()> task);

    void ExecAcquireProviderTask(int32_t userId);

    void AddAcquireProviderForbiddenTask(const std::string &bundleName, int64_t formId, std::function<void()> task);

    void ExecAcquireProviderForbiddenTask(const std::string &bundleName);

    void ExecAcquireProviderForbiddenTaskByFormId(const int64_t formId);

    void DeleteAcquireForbiddenTasksByBundleName(const std::string &bundleName);

    void DeleteAcquireForbiddenTaskByFormId(int64_t formId);

    void AddPostRenderFormTask(int64_t formId, std::function<void()> task);

    void ExecPostRenderFormTask(int64_t formId);

    void DeletePostRenderFormTask(int64_t formId);

    void PostOnUnlockTask();

    ErrCode RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost);

    ErrCode RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams);

    void UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth,
        float formViewScale);

    void DisconnectAllRenderConnections(int32_t userId);

    void RerenderAllFormsImmediate(int32_t userId);

    bool CheckMultiAppFormVersionCode(const FormRecord &formRecord);

    bool GetFRSDiedInLowMemoryByUid(int32_t userId);

    bool GetFormRenderMgrInner(int32_t userId, std::shared_ptr<FormRenderMgrInner> &renderInner);

    bool GetFormSandboxMgrInner(int32_t userId,
        std::shared_ptr<FormSandboxRenderMgrInner> &sandboxInner);

private:
    void InitRenderInner(bool isSandbox, int32_t userId);

private:
    mutable std::mutex isVerifiedMutex_;
    std::shared_mutex renderInnerMutex_;
    std::mutex taskQueueMutex_;
    std::unordered_map<int32_t, std::queue<std::function<void()>>> taskQueueMap_;
    std::mutex forbiddenTaskMapMutex_;
    std::unordered_map<std::string, std::unordered_map<int64_t, std::function<void()>>> forbiddenTaskMap_;
    std::mutex renderFormTaskMapMutex_;
    std::unordered_map<int64_t, std::function<void()>> renderFormTaskMap_;
    // <userId, FormRenderMgrInner>
    std::unordered_map<int32_t, std::shared_ptr<FormRenderMgrInner>> renderInners_;
    // <userId, FormSandboxRenderMgrInner>
    std::unordered_map<int32_t, std::shared_ptr<FormSandboxRenderMgrInner>> sandboxInners_;
    bool isScreenUnlocked_ = false;
    bool isVerified_ = false;
    bool isSecondMounted_ = false;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_MGR_H
