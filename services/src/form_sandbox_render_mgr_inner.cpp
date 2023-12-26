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

#include "form_sandbox_render_mgr_inner.h"

#include <mutex>

#include "fms_log_wrapper.h"
#include "form_bms_helper.h"
#include "form_trust_mgr.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t DLP_TYPE = 2;
constexpr int32_t DEFAULT_SANDBOX_FRS_APP_INDEX = 1;
constexpr int32_t DEFAULT_USER = 0;
}
using Want = OHOS::AAFwk::Want;
FormSandboxRenderMgrInner::FormSandboxRenderMgrInner()
{
}
FormSandboxRenderMgrInner::~FormSandboxRenderMgrInner()
{
}

ErrCode FormSandboxRenderMgrInner::IsSandboxFRSInstalled() const
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("GetBundleMgr, failed to get IBundleMgr.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    BundleInfo info;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    ErrCode ret = iBundleMgr->GetSandboxBundleInfo(
        "com.ohos.formrenderservice", DEFAULT_SANDBOX_FRS_APP_INDEX, DEFAULT_USER, info);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}

ErrCode FormSandboxRenderMgrInner::InstallSandboxFRS(int32_t &appIndex) const
{
    HILOG_INFO("InstallSandboxFRS start.");
    sptr<IBundleInstaller> bundleInstallerProxy = FormBmsHelper::GetInstance().GetBundleInstaller();
    if (bundleInstallerProxy == nullptr) {
        HILOG_ERROR("GetBundleInstaller failed.");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }
    return bundleInstallerProxy->InstallSandboxApp("com.ohos.formrenderservice", DLP_TYPE, DEFAULT_USER, appIndex);
}

ErrCode FormSandboxRenderMgrInner::RenderForm(
    const FormRecord &formRecord, Want &want, const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("FormSandboxRenderMgrInner RenderForm start");
    {
        std::lock_guard<std::mutex> lock(sandboxMutex_);
        if (GetRenderRemoteObj() == nullptr && IsSandboxFRSInstalled() != ERR_OK) {
            HILOG_INFO("RenderForm, sandbox frs not installed.");
            int32_t appIndex = 0;
            std::string identity  = IPCSkeleton::ResetCallingIdentity();
            ErrCode ret = InstallSandboxFRS(appIndex);
            IPCSkeleton::SetCallingIdentity(identity);
            if (ret != ERR_OK) {
                HILOG_ERROR("InstallSandboxFRS fail, ret: %{public}d.", ret);
                return ret;
            }
            if (appIndex != 1) {
                HILOG_ERROR("sandbox FRS already install, please check, appIndex: %{public}d.", appIndex);
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
        }
    }

    return FormRenderMgrInner::RenderForm(formRecord, want, hostToken);
}
} // namespace AppExecFwk
} // namespace OHOS
