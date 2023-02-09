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

#include "form_render_impl.h"

#include <cstddef>
#include <memory>

#include "event_handler.h"
#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_render_service_extension.h"
#include "form_supply_proxy.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "js_runtime.h"
#include "service_extension.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
namespace {
constexpr int32_t RENDER_FORM_FAILED = -1;
}
using namespace AbilityRuntime;

static OHOS::AbilityRuntime::ServiceExtension *FormRenderServiceCreator(const std::unique_ptr<Runtime> &runtime)
{
    HILOG_DEBUG("Create FormRenderServiceExtension");
    return FormRenderServiceExtension::Create(runtime);
}

__attribute__((constructor)) void RegisterServiceExtensionCreator()
{
    HILOG_DEBUG("Set FormRenderServiceExtension creator");
    OHOS::AbilityRuntime::ServiceExtension::SetCreator(FormRenderServiceCreator);
}

FormRenderImpl::FormRenderImpl() = default;
FormRenderImpl::~FormRenderImpl() = default;

int32_t FormRenderImpl::RenderForm(const FormJsInfo &formJsInfo, const Want &want,
                                   const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("Render form, bundleName = %{public}s, abilityName = %{public}s, formName = %{public}s,"
        "moduleName = %{public}s, jsFormCodePath = %{public}s, formSrc = %{public}s",
        formJsInfo.bundleName.c_str(), formJsInfo.abilityName.c_str(), formJsInfo.formName.c_str(),
        formJsInfo.moduleName.c_str(), formJsInfo.jsFormCodePath.c_str(), formJsInfo.formSrc.c_str());

    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("%{public}s warn, IFormSupply is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    HILOG_DEBUG("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));

    int32_t uid = want.GetIntParam(Constants::FORM_SUPPLY_UID, 0);
    if (!uid) {
        HILOG_ERROR("GetUid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    int32_t result = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            result = search->second->UpdateRenderRecord(formJsInfo, want, callerToken);
        } else {
            auto record = FormRenderRecord::Create(formJsInfo.bundleName, uid);
            result = record->UpdateRenderRecord(formJsInfo, want, callerToken);
            renderRecordMap_.emplace(uid, record);
        }
    }
    formSupplyClient->OnRenderTaskDone(formJsInfo.formId, want);
    return result;
}

int32_t FormRenderImpl::StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s called.", __func__);
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("%{public}s warn, IFormSupply is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    
    int32_t uid = want.GetIntParam(Constants::FORM_SUPPLY_UID, 0);
    if (!uid) {
        HILOG_ERROR("GetUid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            if (search->second->DeleteRenderRecord(formJsInfo.formId, want, callerToken) != ERR_OK) {
                renderRecordMap_.erase(uid);
            }
        } else {
            HILOG_ERROR("%{public}s StopRenderingForm failed", __func__ );
            return RENDER_FORM_FAILED;
        }
    }

    HILOG_DEBUG("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));

    formSupplyClient->OnStopRenderingTaskDone(formJsInfo.formId, want);
    return ERR_OK;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
