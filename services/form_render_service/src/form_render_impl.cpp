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
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_render_event_report.h"
#include "form_render_service_extension.h"
#include "js_runtime.h"
#include "service_extension.h"
#include "form_memmgr_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
namespace {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr int32_t FORM_RENDER_TASK_DELAY_TIME = 20; // ms
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
                                   sptr<IRemoteObject> callerToken)
{
    HILOG_INFO("Render form, bundleName=%{public}s, abilityName=%{public}s, formName=%{public}s,"
        "moduleName=%{public}s, jsFormCodePath=%{public}s, formSrc=%{public}s, formId=%{public}" PRId64,
        formJsInfo.bundleName.c_str(), formJsInfo.abilityName.c_str(), formJsInfo.formName.c_str(),
        formJsInfo.moduleName.c_str(), formJsInfo.jsFormCodePath.c_str(), formJsInfo.formSrc.c_str(),
        formJsInfo.formId);

    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("%{public}s warn, IFormSupply is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient_ = formSupplyClient;
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
            auto record = FormRenderRecord::Create(formJsInfo.bundleName, uid, formJsInfo.isDynamic);
            if (record == nullptr) {
                HILOG_ERROR("record is nullptr");
                return RENDER_FORM_FAILED;
            }

            record->SetConfiguration(configuration_);
            result = record->UpdateRenderRecord(formJsInfo, want, hostToken);
            if (renderRecordMap_.empty()) {
                FormMemmgrClient::GetInstance().SetCritical(true);
            }
            renderRecordMap_.emplace(uid, record);
            FormRenderGCTask(uid);
        }
    }
    formSupplyClient->OnRenderTaskDone(formJsInfo.formId, want);
    return result;
}

int32_t FormRenderImpl::StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IRemoteObject> &callerToken)
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
            HILOG_ERROR("%{public}s failed", __func__);
            return RENDER_FORM_FAILED;
        }

        if (!search->second) {
            HILOG_ERROR("%{public}s failed", __func__);
            return RENDER_FORM_FAILED;
        }

        std::string compId = want.GetStringParam(Constants::FORM_RENDER_COMP_ID);
        search->second->DeleteRenderRecord(formJsInfo.formId, compId, hostToken, isRenderGroupEmpty);
        if (search->second->IsEmpty()) {
            renderRecordMap_.erase(search);
            HILOG_INFO("DeleteRenderRecord success, uid: %{public}s", uid.c_str());
            if (renderRecordMap_.empty()) {
                FormMemmgrClient::GetInstance().SetCritical(false);
            }
        }
    }

    HILOG_INFO("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));
    if (isRenderGroupEmpty) {
        formSupplyClient->OnStopRenderingTaskDone(formJsInfo.formId, want);
    }

    return ERR_OK;
}

int32_t FormRenderImpl::ReleaseRenderer(int64_t formId, const std::string &compId, const std::string &uid)
{
    HILOG_INFO("%{public}s start.", __func__);
    if (formId <= 0 || compId.empty() || uid.empty()) {
        HILOG_ERROR("param invalid");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    bool isRenderGroupEmpty = false;
    auto search = renderRecordMap_.find(uid);
    if (search == renderRecordMap_.end()) {
        HILOG_ERROR("%{public}s failed", __func__);
        return RENDER_FORM_FAILED;
    }

    if (!search->second) {
        HILOG_ERROR("%{public}s failed", __func__);
        return RENDER_FORM_FAILED;
    }

    search->second->ReleaseRenderer(formId, compId, isRenderGroupEmpty);
    HILOG_INFO("%{public}s end, isRenderGroupEmpty: %{public}d",
        __func__, isRenderGroupEmpty);
    if (isRenderGroupEmpty) {
        search->second->Release();
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
        FormMemmgrClient::GetInstance().SetCritical(false);
    }
    return ERR_OK;
}

int32_t FormRenderImpl::ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
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
        search->second->ReloadFormRecord(std::forward<decltype(formJsInfos)>(formJsInfos), want);
    }
    return ERR_OK;
}

int32_t FormRenderImpl::OnUnlock()
{
    HILOG_INFO("OnUnlock start");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    for (const auto& iter : renderRecordMap_) {
        if (iter.second) {
            iter.second->OnUnlock();
        }
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
    PerformanceEventInfo eventInfo;
    eventInfo.timeStamp = FormRenderEventReport::GetNowMillisecond();
    eventInfo.bundleName = Constants::FRS_BUNDLE_NAME;
    eventInfo.sceneId = Constants::CPU_SCENE_ID_CONFIG_UPDATE;
    FormRenderEventReport::SendPerformanceEvent(SceneType::CPU_SCENE_ENTRY, eventInfo);
}

void FormRenderImpl::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    configuration_ = config;
}

void FormRenderImpl::OnRenderingBlock(const std::string &bundleName)
{
    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }

    if (formSupplyClient == nullptr) {
        HILOG_ERROR("formSupplyClient_ is nullptr");
        return;
    }

    formSupplyClient->OnRenderingBlock(bundleName);
}

void FormRenderImpl::FormRenderGCTask(const std::string &uid)
{
    auto mainHandler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    if (mainHandler == nullptr) {
        HILOG_ERROR("main handler is nullptr");
        return;
    }
    auto formRenderGCFunc = [uid]() {
        auto formRenderImpl = OHOS::DelayedSingleton<FormRenderImpl>::GetInstance();
        if (formRenderImpl == nullptr) {
            HILOG_ERROR("formRenderImpl is nullptr");
            return;
        }
        formRenderImpl->FormRenderGC(uid);
    };
    mainHandler->PostTask(formRenderGCFunc, "FormRenderGC", FORM_RENDER_TASK_DELAY_TIME);
}

void FormRenderImpl::FormRenderGC(const std::string &uid)
{
    HILOG_INFO("form gc, uid is %{s}public", uid.c_str());
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
        search->second->FormRenderGC();
    }
}

int32_t FormRenderImpl::RecycleForm(const int64_t &formId, const Want &want)
{
    HILOG_INFO("formId: %{public}s.", std::to_string(formId).c_str());
    if (formId <= 0) {
        HILOG_ERROR("formId is negative.");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("uid is empty");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    std::string statusData;
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            if (search->second == nullptr) {
                HILOG_ERROR("render record of %{public}s is null.", std::to_string(formId).c_str());
                return RECYCLE_FORM_FAILED;
            }
            search->second->RecycleForm(formId, statusData);
        } else {
            HILOG_ERROR("can't find render record of %{public}s.", std::to_string(formId).c_str());
            return RECYCLE_FORM_FAILED;
        }
        if (statusData.empty()) {
            HILOG_WARN("statusData of %{public}s is empty.", std::to_string(formId).c_str());
        }
    }

    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("formSupplyClient_ is null");
        return RECYCLE_FORM_FAILED;
    }

    Want newWant = want;
    newWant.SetParam(Constants::FORM_STATUS_DATA, statusData);
    formSupplyClient->OnRecycleForm(formId, newWant);
    return ERR_OK;
}

int32_t FormRenderImpl::RecoverForm(const int64_t &formId, const Want &want)
{
    HILOG_INFO("formId:%{public}s, connectId: %{public}d.",
        std::to_string(formId).c_str(), want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));
    if (formId <= 0) {
        HILOG_ERROR("formId is negative.");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("uid is empty");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
    if (statusData.empty()) {
        HILOG_WARN("statusData of %{public}s is empty", std::to_string(formId).c_str());
    }

    bool isRecoverFormToHandleClickEvent = want.GetBoolParam(
        Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, false);
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
        if (search->second == nullptr) {
            HILOG_ERROR("render record of %{public}s is null.", std::to_string(formId).c_str());
            return RECYCLE_FORM_FAILED;
        }
        return search->second->RecoverForm(formId, statusData, isRecoverFormToHandleClickEvent);
    }
    HILOG_ERROR("can't find render record of %{public}s.", std::to_string(formId).c_str());
    return RENDER_FORM_FAILED;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
