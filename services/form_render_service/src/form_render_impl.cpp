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
#ifdef SUPPORT_POWER
#include "power_mgr_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
namespace {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr int32_t SET_VISIBLE_CHANGE_FAILED = -1;
constexpr int32_t FORM_RENDER_TASK_DELAY_TIME = 20; // ms
constexpr int32_t ENABLE_FORM_FAILED = -1;
constexpr int32_t UPDATE_FORM_SIZE_FAILED = -1;
}
using namespace AbilityRuntime;
using namespace OHOS::AAFwk::GlobalConfigurationKey;

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

FormRenderImpl::FormRenderImpl()
{
    const std::string queueName = "FormRenderSerialQueue";
    serialQueue_ = std::make_shared<FormRenderSerialQueue>(queueName);
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
    }
}

FormRenderImpl::~FormRenderImpl() = default;

int32_t FormRenderImpl::RenderForm(const FormJsInfo &formJsInfo, const Want &want,
    sptr<IRemoteObject> callerToken)
{
    HILOG_INFO("Render form,bundleName=%{public}s,abilityName=%{public}s,formName=%{public}s,"
        "moduleName=%{public}s,jsFormCodePath=%{public}s,formSrc=%{public}s,formId=%{public}" PRId64,
        formJsInfo.bundleName.c_str(), formJsInfo.abilityName.c_str(), formJsInfo.formName.c_str(),
        formJsInfo.moduleName.c_str(), formJsInfo.jsFormCodePath.c_str(), formJsInfo.formSrc.c_str(),
        formJsInfo.formId);

    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        if (formSupplyClient == nullptr) {
            HILOG_ERROR("null IFormSupply");
            return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
        }
        formSupplyClient_ = formSupplyClient;
    }
    HILOG_DEBUG("connectId:%{public}d",
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("GetUid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    int32_t result = ERR_OK;
    Want formRenderWant(want);
    sptr<IRemoteObject> hostToken = formRenderWant.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        ConfirmUnlockState(formRenderWant);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            result = search->second->UpdateRenderRecord(formJsInfo, formRenderWant, hostToken);
        } else {
            auto record = FormRenderRecord::Create(formJsInfo.bundleName, uid, formJsInfo.isDynamic, formSupplyClient);
            if (record == nullptr) {
                HILOG_ERROR("null record");
                return RENDER_FORM_FAILED;
            }

            record->SetConfiguration(configuration_);
            result = record->UpdateRenderRecord(formJsInfo, formRenderWant, hostToken);
            if (renderRecordMap_.empty()) {
                FormMemmgrClient::GetInstance().SetCritical(true);
            }
            renderRecordMap_.emplace(uid, record);
            FormRenderGCTask(uid);
        }
    }
    formSupplyClient->OnRenderTaskDone(formJsInfo.formId, formRenderWant);
    return result;
}

int32_t FormRenderImpl::StopRenderingForm(const FormJsInfo &formJsInfo, const Want &want,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call");
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null IFormSupply");
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
        std::shared_ptr<FormRenderRecord> search = nullptr;
        {
            std::lock_guard<std::mutex> lock(renderRecordMutex_);
            auto iterator = renderRecordMap_.find(uid);
            if (iterator == renderRecordMap_.end() || !(iterator->second)) {
                HILOG_ERROR("fail");
                return RENDER_FORM_FAILED;
            }
            search = iterator->second;
        }

        std::string compId = want.GetStringParam(Constants::FORM_RENDER_COMP_ID);
        search->DeleteRenderRecord(formJsInfo.formId, compId, hostToken, isRenderGroupEmpty);
        {
            std::lock_guard<std::mutex> lock(renderRecordMutex_);
            if (search->IsEmpty() && !search->HasRenderFormTask()) {
                auto iterator = renderRecordMap_.find(uid);
                if (iterator == renderRecordMap_.end()) {
                    HILOG_ERROR("fail.");
                    return RENDER_FORM_FAILED;
                }
                renderRecordMap_.erase(iterator);
                HILOG_INFO("DeleteRenderRecord success,uid:%{public}s", uid.c_str());
                if (renderRecordMap_.empty()) {
                    FormMemmgrClient::GetInstance().SetCritical(false);
                }
            }
        }
    }

    HILOG_INFO("connectId:%{public}d",
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));
    if (isRenderGroupEmpty) {
        formSupplyClient->OnStopRenderingTaskDone(formJsInfo.formId, want);
    }

    return ERR_OK;
}

int32_t FormRenderImpl::ReleaseRenderer(int64_t formId, const std::string &compId, const std::string &uid)
{
    HILOG_INFO("formId:%{public}" PRId64 ",compId:%{public}s,uid:%{public}s", formId, compId.c_str(), uid.c_str());
    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
    }

    if (formId <= 0 || compId.empty() || uid.empty()) {
        HILOG_ERROR("param invalid");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    bool isRenderGroupEmpty = false;
    auto search = renderRecordMap_.find(uid);
    if (search == renderRecordMap_.end()) {
        HILOG_ERROR("invalid record,formId:%{public}" PRId64, formId);
        return RENDER_FORM_FAILED;
    }

    if (!search->second) {
        HILOG_ERROR("record invalid,formId:%{public}" PRId64, formId);
        return RENDER_FORM_FAILED;
    }

    search->second->ReleaseRenderer(formId, compId, isRenderGroupEmpty);
    HILOG_INFO("end,isRenderGroupEmpty:%{public}d", isRenderGroupEmpty);
    formSupplyClient->OnRecycleFormDone(formId);
    if (isRenderGroupEmpty) {
        search->second->Release();
    }

    return ERR_OK;
}

int32_t FormRenderImpl::CleanFormHost(const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("Form host is died,clean renderRecord");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    for (auto iter = renderRecordMap_.begin(); iter != renderRecordMap_.end();) {
        auto renderRecord = iter->second;
        if (renderRecord && renderRecord->HandleHostDied(hostToken)) {
            HILOG_DEBUG("empty renderRecord,remove");
            iter = renderRecordMap_.erase(iter);
        } else {
            ++iter;
        }
    }
    if (renderRecordMap_.empty()) {
        HILOG_INFO("empty renderRecordMap_,FormRenderService will exit later");
        FormMemmgrClient::GetInstance().SetCritical(false);
    }
    return ERR_OK;
}

int32_t FormRenderImpl::ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want)
{
    HILOG_INFO("ReloadForm start");
    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("Get uid failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    std::shared_ptr<FormRenderRecord> search = nullptr;
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        auto iterator = renderRecordMap_.find(uid);
        if (iterator == renderRecordMap_.end()) {
            HILOG_ERROR("RenderRecord not find");
            return RELOAD_FORM_FAILED;
        }
        search = iterator->second;
    }
    if (search != nullptr) {
        search->ReloadFormRecord(std::forward<decltype(formJsInfos)>(formJsInfos), want);
    }
    return ERR_OK;
}

int32_t FormRenderImpl::OnUnlock()
{
    HILOG_INFO("OnUnlock start");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (isVerified_) {
        HILOG_WARN("Has been unlocked in render form, maybe miss or delay unlock event");
        return ERR_OK;
    }

    isVerified_ = true;
    for (const auto& iter : renderRecordMap_) {
        if (iter.second) {
            iter.second->OnUnlock();
        }
    }
    return ERR_OK;
}

int32_t FormRenderImpl::SetVisibleChange(const int64_t &formId, bool isVisible, const Want &want)
{
    HILOG_INFO("SetVisibleChange start");
    if (formId <= 0) {
        HILOG_ERROR("formId is negative");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("empty uid,formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    HILOG_INFO("formId:%{public}" PRId64 ",uid:%{public}s", formId, uid.c_str());

    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
        if (search->second == nullptr) {
            HILOG_ERROR("null renderRecord of %{public}s", std::to_string(formId).c_str());
            return SET_VISIBLE_CHANGE_FAILED;
        }
        auto ret = search->second->SetVisibleChange(formId, isVisible);
        if (ret != ERR_OK) {
            return ret;
        }
    } else {
        HILOG_ERROR("can't find render record of %{public}s", std::to_string(formId).c_str());
        return SET_VISIBLE_CHANGE_FAILED;
    }
    return ERR_OK;
}

void FormRenderImpl::OnConfigurationUpdated(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& configuration)
{
    HILOG_DEBUG("OnConfigurationUpdated start");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (!configuration) {
        HILOG_ERROR("null configuration");
        return;
    }

    SetConfiguration(configuration);

#ifdef SUPPORT_POWER
    bool screenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsScreenOn();
    bool collaborationScreenOnFlag = PowerMgr::PowerMgrClient::GetInstance().IsCollaborationScreenOn();
    if (!screenOnFlag && !collaborationScreenOnFlag) {
        HILOG_WARN("screen off");
        hasCachedConfig_ = true;
        return;
    }
#endif

    constexpr int64_t minDurationMs = 1500;
    const std::string taskName = "FormRenderImpl::OnConfigurationUpdated";
    serialQueue_->CancelDelayTask(taskName);
    auto duration = std::chrono::steady_clock::now() - configUpdateTime_;
    if (std::chrono::duration_cast<std::chrono::milliseconds>(duration).count() < minDurationMs) {
        HILOG_INFO("OnConfigurationUpdated ignored");
        auto configUpdateFunc = [this]() {
            HILOG_INFO("OnConfigurationUpdated task run");
            this->OnConfigurationUpdatedInner();
        };
        constexpr int64_t taskDelayMs = 1000;
        serialQueue_->ScheduleDelayTask(taskName, taskDelayMs, configUpdateFunc);
        return;
    }
    OnConfigurationUpdatedInner();
}

void FormRenderImpl::OnConfigurationUpdatedInner()
{
    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient");
    }

    configUpdateTime_ = std::chrono::steady_clock::now();
    size_t allFormCount = 0;
    for (auto iter = renderRecordMap_.begin(); iter != renderRecordMap_.end(); ++iter) {
        if (iter->second) {
            iter->second->UpdateConfiguration(configuration_, formSupplyClient);
            allFormCount += iter->second->FormCount();
        }
    }
    HILOG_INFO("OnConfigurationUpdated %{public}zu forms updated.", allFormCount);
    hasCachedConfig_ = false;
    PerformanceEventInfo eventInfo;
    eventInfo.timeStamp = FormRenderEventReport::GetNowMillisecond();
    eventInfo.bundleName = Constants::FRS_BUNDLE_NAME;
    eventInfo.sceneId = Constants::CPU_SCENE_ID_CONFIG_UPDATE;
    FormRenderEventReport::SendPerformanceEvent(SceneType::CPU_SCENE_ENTRY, eventInfo);
}

void FormRenderImpl::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    if (config != nullptr && configuration_ != nullptr) {
        std::string colorMode = config->GetItem(SYSTEM_COLORMODE);
        std::string languageTag = config->GetItem(SYSTEM_LANGUAGE);
        std::string colorModeOld = configuration_->GetItem(SYSTEM_COLORMODE);
        std::string languageTagOld = configuration_->GetItem(SYSTEM_LANGUAGE);
        configuration_ = config;
        if (colorMode.empty()) {
            configuration_->AddItem(SYSTEM_COLORMODE, colorModeOld);
        }
        if (languageTag.empty()) {
            configuration_->AddItem(SYSTEM_LANGUAGE, languageTagOld);
        }
        return;
    }

    configuration_ = config;
}

void FormRenderImpl::RunCachedConfigurationUpdated()
{
    HILOG_INFO("RunCachedConfigUpdated");
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (hasCachedConfig_) {
        OnConfigurationUpdatedInner();
    }
}

void FormRenderImpl::FormRenderGCTask(const std::string &uid)
{
    auto mainHandler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    if (mainHandler == nullptr) {
        HILOG_ERROR("null mainHandler");
        return;
    }
    auto formRenderGCFunc = [uid]() {
        auto formRenderImpl = OHOS::DelayedSingleton<FormRenderImpl>::GetInstance();
        if (formRenderImpl == nullptr) {
            HILOG_ERROR("null formRenderImpl");
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
    if (formId <= 0) {
        HILOG_ERROR("formId is negative");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("empty uid,formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    HILOG_INFO("formId:%{public}" PRId64 ",uid:%{public}s", formId, uid.c_str());

    std::string statusData;
    {
        std::lock_guard<std::mutex> lock(renderRecordMutex_);
        if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
            if (search->second == nullptr) {
                HILOG_ERROR("null renderRecord of %{public}s", std::to_string(formId).c_str());
                return RECYCLE_FORM_FAILED;
            }
            auto ret = search->second->RecycleForm(formId, statusData);
            if (ret != ERR_OK) {
                return ret;
            }
        } else {
            HILOG_ERROR("can't find render record of %{public}s", std::to_string(formId).c_str());
            return RECYCLE_FORM_FAILED;
        }
        if (statusData.empty()) {
            HILOG_WARN("empty statusData of %{public}s", std::to_string(formId).c_str());
        }
    }

    sptr<IFormSupply> formSupplyClient = nullptr;
    {
        std::lock_guard<std::mutex> lock(formSupplyMutex_);
        formSupplyClient = formSupplyClient_;
    }
    if (formSupplyClient == nullptr) {
        HILOG_ERROR("null formSupplyClient, formId:%{public}" PRId64, formId);
        return RECYCLE_FORM_FAILED;
    }

    Want newWant = want;
    newWant.SetParam(Constants::FORM_STATUS_DATA, statusData);
    formSupplyClient->OnRecycleForm(formId, newWant);
    return ERR_OK;
}

int32_t FormRenderImpl::RecoverForm(const FormJsInfo &formJsInfo, const Want &want)
{
    auto formId = formJsInfo.formId;
    if (formId <= 0) {
        HILOG_ERROR("formId is negative");
        return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string uid = want.GetStringParam(Constants::FORM_SUPPLY_UID);
    if (uid.empty()) {
        HILOG_ERROR("empty uid,formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    HILOG_INFO("formId:%{public}" PRId64 ", connectId:%{public}d, uid:%{public}s",
        formId, want.GetIntParam(Constants::FORM_CONNECT_ID, 0L), uid.c_str());

    std::string statusData = want.GetStringParam(Constants::FORM_STATUS_DATA);
    if (statusData.empty()) {
        HILOG_WARN("empty statusData of %{public}s", std::to_string(formId).c_str());
    }

    bool isRecoverFormToHandleClickEvent = want.GetBoolParam(
        Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, false);
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
        if (search->second == nullptr) {
            HILOG_ERROR("null renderRecord of %{public}s", std::to_string(formId).c_str());
            return RECYCLE_FORM_FAILED;
        }
        return search->second->RecoverForm(formJsInfo, statusData, isRecoverFormToHandleClickEvent);
    }
    HILOG_ERROR("can't find render record of %{public}s", std::to_string(formId).c_str());
    return RENDER_FORM_FAILED;
}

void FormRenderImpl::ConfirmUnlockState(Want &renderWant)
{
    // Ensure that there are no issues with adding form and unlocking drawing concurrency
    if (isVerified_) {
        renderWant.SetParam(Constants::FORM_RENDER_STATE, true);
    } else if (renderWant.GetBoolParam(Constants::FORM_RENDER_STATE, false)) {
        HILOG_WARN("Maybe unlock event is missed or delayed, all form record begin to render");
        isVerified_ = true;
        for (const auto& iter : renderRecordMap_) {
            if (iter.second) {
                iter.second->OnUnlock();
            }
        }
    }
}

int32_t FormRenderImpl::UpdateFormSize(
    const int64_t &formId, float width, float height, float borderWidth, const std::string &uid)
{
    std::lock_guard<std::mutex> lock(renderRecordMutex_);
    if (auto search = renderRecordMap_.find(uid); search != renderRecordMap_.end()) {
        if (search->second == nullptr) {
            HILOG_ERROR("UpdateFormSize null renderRecord of %{public}" PRId64, formId);
            return UPDATE_FORM_SIZE_FAILED;
        }
        search->second->UpdateFormSizeOfGroups(formId, width, height, borderWidth);
        return ERR_OK;
    }
    HILOG_ERROR("can't find render record of %{public}" PRId64, formId);
    return UPDATE_FORM_SIZE_FAILED;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
