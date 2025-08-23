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

#ifndef OHOS_FORM_FWK_FORM_RENDER_SERVICE_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_SERVICE_MGR_H

#include "form_render_stub.h"

#include <memory>
#include <singleton.h>

#include "bundle_mgr_interface.h"
#include "context_impl.h"
#include "event_handler.h"
#include "form_supply_proxy.h"
#include "form_render_record.h"
#include "form_render_serial_queue.h"
#include "js_runtime.h"
#include "runtime.h"
#include "want.h"
#include "status_mgr_center/form_status_common.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using OHOS::AAFwk::Want;
using namespace AbilityRuntime;

class FormRenderServiceMgr final : public DelayedRefSingleton<FormRenderServiceMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderServiceMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderServiceMgr);

    /**
     * @brief Render form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Stop rendering form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief When host is died, clean resources. This is async API.
     * @param hostToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t CleanFormHost(const sptr<IRemoteObject> &hostToken);

    /**
     * @brief Reload form When app updated. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @return int32_t Returns ERR_OK on success, others on failure.
     */
    int32_t ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want);

    /**
     * @brief Called when the system configuration is updated.
     * @param configuration Indicates the updated configuration information.
     */
    void OnConfigurationUpdated(const std::shared_ptr<OHOS::AppExecFwk::Configuration> &configuration);

    /**
     * @brief Called when the system start.
     * @param config Indicates the updated configuration information.
     */
    void SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration> &config);

    void RunCachedConfigurationUpdated();

    int32_t ReleaseRenderer(int64_t formId, const std::string &compId, const std::string &uid, const Want &want);

    int32_t OnUnlock();

    int32_t SetVisibleChange(const int64_t formId, bool isVisible, const Want &want);

    int32_t RecycleForm(const int64_t formId, const Want &want);

    int32_t RecoverForm(const FormJsInfo &formJsInfo, const Want &want);

    int32_t UpdateFormSize(const int64_t formId, float width, float height, float borderWidth, const std::string &uid);

    void SetFormSupplyClient(const sptr<IFormSupply> &formSupplyClient);

    sptr<IFormSupply> GetFormSupplyClient();

    void SetCriticalFalseOnAllFormInvisible();
    
    void SetCriticalTrueOnFormActivity();

private:
    void FormRenderGCTask(const std::string &uid);
    void FormRenderGC(const std::string &uid);
    void OnConfigurationUpdatedInner();
    void ConfirmUnlockState(Want &renderWant);
    int32_t UpdateRenderRecordByUid(const std::string &uid, Want &formRenderWant, const FormJsInfo &formJsInfo,
        const sptr<IFormSupply> &formSupplyClient);
    bool IsRenderRecordExist(const std::string &uid);
    void GetRenderRecordById(std::shared_ptr<FormRenderRecord> &search, const std::string &uid);
    int32_t RecoverFormByUid(
        const FormJsInfo &formJsInfo, const Want &want, const std::string &uid, const std::string &statusData);
    int32_t RecycleFormByUid(const std::string &uid, std::string &statusData, const int64_t formId);
    int32_t DeleteRenderRecordByUid(const std::string &uid, const std::shared_ptr<FormRenderRecord> &search);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> GetNeedApplyConfig();
    void CacheAppliedConfig();
    int32_t ReloadFormRecord(const std::vector<FormJsInfo> &&formJsInfos, const Want &want);

private:
    std::mutex renderRecordMutex_;
    // <uid(userId + bundleName), renderRecord>
    std::unordered_map<std::string, std::shared_ptr<FormRenderRecord>> renderRecordMap_;
    std::mutex configMutex_;
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration_;
    // The configuration items have already been applied to ArkUI.
    std::shared_ptr<OHOS::AppExecFwk::Configuration> appliedConfig_;
    std::chrono::steady_clock::time_point configUpdateTime_ = std::chrono::steady_clock::now();
    std::shared_ptr<FormRenderSerialQueue> serialQueue_ = nullptr;
    std::mutex formSupplyMutex_;
    sptr<IFormSupply> formSupplyClient_;
    bool isVerified_ = false;
    bool hasCachedConfig_ = false;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_SERVICE_MGR_H
