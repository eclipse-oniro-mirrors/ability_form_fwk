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
#include "form_render_serial_queue.h"
#include "form_supply_proxy.h"
#include "js_runtime.h"
#include "runtime.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using OHOS::AAFwk::Want;
using namespace AbilityRuntime;

class FormRenderImpl : public FormRenderStub, public std::enable_shared_from_this<FormRenderImpl> {
    DECLARE_DELAYED_SINGLETON(FormRenderImpl)
public:
    /**
     * @brief Render form. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want, sptr<IRemoteObject> callerToken) override;

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
    int32_t ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want) override;

    void RunCachedConfigurationUpdated() override;

    int32_t ReleaseRenderer(
        int64_t formId, const std::string &compId, const std::string &uid, const Want &want) override;

    int32_t OnUnlock() override;

    int32_t SetVisibleChange(const int64_t &formId, bool isVisible, const Want &want) override;

    int32_t RecycleForm(const int64_t &formId, const Want &want) override;

    int32_t RecoverForm(const FormJsInfo &formJsInfo, const Want &want) override;

    int32_t UpdateFormSize(
        const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo, const std::string &uid) override;

protected:
    int32_t CheckPermission() override;

private:
    bool CheckIsFoundationCall();
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_IMPL_H
