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
constexpr int32_t RELOAD_FORM_FAILED = -1;
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

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("GetUid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    int32_t result = ERR_OK;
    sptr<IRemoteObject> hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            result = search->second->UpdateRenderRecord(formJsInfo, want, hostToken);
        } else {
            auto record = FormRenderRecord::Create(formJsInfo.bundleName, uid);
            if (record == nullptr) {
                HILOG_ERROR("record is nullptr");
                return RENDER_FORM_FAILED;
            }

            record->SetConfiguration(configuration_);
            result = record->UpdateRenderRecord(formJsInfo, want, hostToken);
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

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("GetUid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    bool isRenderGroupEmpty = false;
    sptr<IRemoteObject> hostToken = want.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        auto search = renderRecordMap_.find(uid);
        if (search == renderRecordMap_.end()) {
            HILOG_ERROR("%{public}s failed", __func__ );
            return RENDER_FORM_FAILED;
        }

        if (!search->second) {
            HILOG_ERROR("%{public}s failed", __func__ );
            return RENDER_FORM_FAILED;
        }

        std::string compId = want.GetStringParam(Constants::FORM_RENDER_COMP_ID);
        search->second->DeleteRenderRecord(formJsInfo.formId, compId, hostToken, isRenderGroupEmpty);
        if (search->second->IsEmpty()) {
            renderRecordMap_.erase(search);
            HILOG_INFO("DeleteRenderRecord success, uid: %{public}s", uid.c_str());
        }
    }

    HILOG_INFO("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));
    if (isRenderGroupEmpty) {
        formSupplyClient->OnStopRenderingTaskDone(formJsInfo.formId, want);
    }

    return ERR_OK;
}

int32_t FormRenderImpl::CleanFormHost(const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("Form host is died, clean renderRecord.");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    for (auto iter = renderRecordMap_.begin(); iter != renderRecordMap_.end();) {
        auto renderRecord = iter->second;
        if (renderRecord && renderRecord->HandleHostDied(hostToken)) {
            HILOG_DEBUG("renderRecord is empty, remove.");
            iter = renderRecordMap_.erase(iter);
        } else {
            ++iter;
        }
    }
    if (renderRecordMap_.empty()) {
        HILOG_INFO("renderRecordMap_ is empty, FormRenderService will exit later.");
    }
    return ERR_OK;
}

int32_t FormRenderImpl::ReloadForm(const std::vector<int64_t> &&formIds, const Want &want)
{
    HILOG_INFO("ReloadForm start");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("Get uid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    auto search = renderRecordMap_.find(uid);
    if (search == renderRecordMap_.end()) {
        HILOG_ERROR("RenderRecord not find");
        return RELOAD_FORM_FAILED;
    }
    if (search->second) {
        search->second->ReloadFormRecord(std::forward<decltype(formIds)>(formIds), want);
    }
    return ERR_OK;
}

void FormRenderImpl::OnConfigurationUpdated(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& configuration)
{
    HILOG_INFO("OnConfigurationUpdated start");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (!configuration) {
        HILOG_ERROR("configuration is nullptr");
        return;
    }

    SetConfiguration(configuration);
    for (auto iter = renderRecordMap_.begin(); iter != renderRecordMap_.end(); ++iter) {
        if (iter->second) {
            iter->second->UpdateConfiguration(configuration);
        }
    }
}

void FormRenderImpl::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    configuration_ = config;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
