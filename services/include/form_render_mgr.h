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

#include "form_record.h"
#include "form_render_connection.h"
#include "form_render_interface.h"
#include "form_render_mgr_inner.h"
#include "form_sandbox_render_mgr_inner.h"
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

    void OnUnlock();

    ErrCode StopRenderingForm(int64_t formId, const FormRecord &formRecord,
        const std::string &compId = "", const sptr<IRemoteObject> &hostToken = nullptr);

    ErrCode ReloadForm(const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId);

    ErrCode RenderFormCallback(int64_t formId, const Want &want);

    ErrCode StopRenderingFormCallback(int64_t formId, const Want &want);

    void GetFormRenderState() const;

    bool GetIsVerified() const;

    ErrCode AddConnection(int64_t formId, sptr<FormRenderConnection> connection, int32_t privacyLevel);

    void RemoveConnection(int64_t formId, int32_t privacyLevel);

    void AddRenderDeathRecipient(const sptr<IRemoteObject> &renderRemoteObj, int32_t privacyLevel);

    bool IsNeedRender(int64_t formId);

    void CleanFormHost(const sptr<IRemoteObject> &host);

    void HandleConnectFailed(int64_t formId, int32_t errorCode) const;

    bool IsRerenderForRenderServiceDied(int64_t formId);

    void OnRenderingBlock(const std::string &bundleName);

    ErrCode ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId);

    void SetFormRenderState(bool isVerified);

    void AddAcquireProviderFormInfoTask(std::function<void()> task);

    void ExecAcquireProviderTask();

    void PostOnUnlockTask();

    ErrCode RecycleForms(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &remoteObjectOfHost);

    ErrCode RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams);

private:
    void InitRenderInner(bool isSandbox);

private:
    mutable std::mutex isVerifiedMutex_;
    std::mutex renderInnerMutex_;
    std::mutex taskQueueMutex_;
    std::queue<std::function<void()>> taskQueue_;
    std::shared_ptr<FormRenderMgrInner> renderInner_ = nullptr;
    std::shared_ptr<FormSandboxRenderMgrInner> sandboxInner_ = nullptr;
    mutable bool isVerified_ = false;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_MGR_H
