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

#ifndef OHOS_FORM_FWK_FORM_RENDER_IMPL_H
#define OHOS_FORM_FWK_FORM_RENDER_IMPL_H

#include "form_render_stub.h"

#include <memory>
#include <singleton.h>

#include "bundle_mgr_interface.h"
#include "context_impl.h"
#include "event_handler.h"
#include "form_render_record.h"
#include "js_runtime.h"
#include "runtime.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using OHOS::AAFwk::Want;
using namespace AbilityRuntime;

class FormRenderImpl : public FormRenderStub,
                       public std::enable_shared_from_this<FormRenderImpl> {
    DECLARE_DELAYED_SINGLETON(FormRenderImpl)
public:
    /**
     * @brief Render form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Stop rendering form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t StopRenderingForm(
        const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief When host is died, clean resources. This is async API.
     * @param hostToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t CleanFormHost(const sptr<IRemoteObject> &hostToken) override;
    
    /**
     * @brief Reload form When app updated. This is sync API.
     * @param formIds the form id need to update.
     * @param want Indicates the {@link Want} structure containing form info.
     * @return int32_t Returns ERR_OK on success, others on failure.
     */
    int32_t ReloadForm(const std::vector<int64_t> &&formIds, const Want &want) override;

    /**
     * @brief Called when the system configuration is updated.
     * @param configuration Indicates the updated configuration information.
     */
    void OnConfigurationUpdated(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& configuration);

    void SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config);

private:
    std::mutex renderRecordMutex_;
    std::unordered_map<std::string, std::shared_ptr<FormRenderRecord>> renderRecordMap_; // <uid(userId + bundleName), renderRecord>
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration_;
};
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_IMPL_H
