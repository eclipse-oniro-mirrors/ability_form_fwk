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

#include "form_render_record.h"

#include <utility>

#include "form_constants.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RELOAD_FORM_FAILED = -1;

std::shared_ptr<FormRenderRecord> FormRenderRecord::Create(const std::string &bundleName, const std::string &uid)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::shared_ptr<FormRenderRecord> renderRecord = std::make_shared<FormRenderRecord>(bundleName, uid);
    if (!renderRecord) {
        HILOG_ERROR("Create FormRenderRecord failed.");
        return nullptr;
    }

    if (!renderRecord->CreateEventHandler(bundleName)) {
        HILOG_ERROR("CreateEventHandler failed.");
        return nullptr;
    }
    return renderRecord;
}

FormRenderRecord::FormRenderRecord(
    const std::string &bundleName, const std::string &uid) : bundleName_(bundleName), uid_(uid) {}

FormRenderRecord::~FormRenderRecord()
{
    // Some resources need to be deleted in a JS thread
    auto syncTask = [renderRecord = this]() {
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleDestroyInJsThread();
    };
    eventHandler_->PostSyncTask(syncTask);
}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Form host is died, clean resources.");
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    for (auto iter = hostsMapForFormId_.begin(); iter != hostsMapForFormId_.end();) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
        hosts.erase(hostRemoteObj);
        if (hosts.empty()) {
            iter = hostsMapForFormId_.erase(iter);
        } else {
            ++iter;
        }
    }
    return hostsMapForFormId_.empty();
}

bool FormRenderRecord::CreateEventHandler(const std::string &bundleName)
{
    HILOG_INFO("%{public}s called.", __func__);
    if (eventHandler_) {
        HILOG_DEBUG("EventHandle is exist, no need to create a new one.");
        return true;
    }
    // Create event runner
    HILOG_INFO("Create eventHandle.");
    if (eventRunner_ == nullptr) {
        eventRunner_ = EventRunner::Create(bundleName);
        if (eventRunner_ == nullptr) {
            HILOG_ERROR("Create event runner Failed.");
            return false;
        }
    }
    // Create event handler
    eventHandler_ = std::make_shared<EventHandler>(eventRunner_);
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("Create event handler failed.");
        return false;
    }
    return true;
}

int32_t FormRenderRecord::UpdateRenderRecord(const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> hostRemoteObj)
{
    HILOG_INFO("Updated record.");

    // Some resources need to be initialized in a JS thread
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formJsInfo, want]() {
        HILOG_DEBUG("HandleUpdateInJsThread begin.");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleUpdateInJsThread(formJsInfo, want);
    };

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return RENDER_FORM_FAILED;
    }
    eventHandler_->PostTask(task);

    if (hostRemoteObj == nullptr) {
        HILOG_ERROR("hostRemoteObj is nullptr");
        return RENDER_FORM_FAILED;
    }
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto iter = hostsMapForFormId_.find(formJsInfo.formId);
    if (iter == hostsMapForFormId_.end()) {
        hostsMapForFormId_.emplace(formJsInfo.formId, IRemoteObjectSet({ hostRemoteObj }));
        return ERR_OK;
    }
    iter->second.emplace(hostRemoteObj);
    return ERR_OK;
}

void FormRenderRecord::DeleteRenderRecord(int64_t formId, const std::string &compId, const sptr<IRemoteObject> hostRemoteObj, bool &isRenderGroupEmpty)
{
    // Some resources need to be deleted in a JS thread
    HILOG_INFO("Delete some resources formId:%{public}s %{public}s", std::to_string(formId).c_str(), compId.c_str());
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return;
    }

    auto task = [weak = weak_from_this(), formId, compId, &isRenderGroupEmpty]() {
        auto renderRecord = weak.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }

        isRenderGroupEmpty = renderRecord->HandleDeleteInJsThread(formId, compId);
    };

    if (hostRemoteObj != nullptr) {
        std::lock_guard<std::mutex> lock(hostsMapMutex_);
        auto iter = hostsMapForFormId_.find(formId);
        if (iter != hostsMapForFormId_.end()) {
            std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = iter->second;
            hosts.erase(hostRemoteObj);
        }
    }
    eventHandler_->PostSyncTask(task);
}

bool FormRenderRecord::IsEmpty()
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    return formRendererGroupMap_.empty();
}

std::string FormRenderRecord::GetUid() const
{
    return uid_;
}

bool FormRenderRecord::CreateRuntime(const FormJsInfo &formJsInfo)
{
    if (runtime_) {
        HILOG_DEBUG("runtime is exist, no need to create a new one.");
        return true;
    }

    HILOG_INFO("Create a new runtime.");
    if (eventRunner_ == nullptr) {
        HILOG_ERROR("eventRunner_ is nullptr");
        return false;
    }
    AbilityRuntime::Runtime::Options options;
    options.bundleName = formJsInfo.bundleName;
    options.codePath = Constants::LOCAL_CODE_PATH;
    BundleInfo bundleInfo;
    options.eventRunner = eventRunner_;
    options.hapPath = formJsInfo.jsFormCodePath;
    options.loadAce = true;
    options.isBundle = true;
    options.isUnique = true;
    runtime_ = AbilityRuntime::Runtime::Create(options);
    if (runtime_ == nullptr) {
        HILOG_ERROR("Create runtime Failed!");
        return false;
    }
    return true;
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::GetContext(const FormJsInfo &formJsInfo, const Want &want)
{
    {
        std::lock_guard<std::mutex> lock(contextsMapMutex_);
        auto iter = contextsMapForModuleName_.find(GenerateContextKey(formJsInfo));
        if (iter != contextsMapForModuleName_.end()) {
            HILOG_DEBUG("Find context.");
            return iter->second;
        }
    }

    return CreateContext(formJsInfo, want);
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::CreateContext(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Create a new context.");
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (context == nullptr) {
        HILOG_ERROR("Create context failed!");
        return nullptr;
    }

    context->SetConfiguration(configuration_);
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = formJsInfo.moduleName;
    hapModuleInfo.hapPath = formJsInfo.jsFormCodePath;
    hapModuleInfo.compileMode = static_cast<CompileMode>(want.GetIntParam(Constants::FORM_COMPILE_MODE_KEY,
        static_cast<int32_t>(CompileMode::ES_MODULE)));
    context->InitHapModuleInfo(hapModuleInfo);
    auto applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = formJsInfo.bundleName;
    applicationInfo->minCompatibleVersionCode = want.GetIntParam(Constants::FORM_COMPATIBLE_VERSION_CODE_KEY, 0);
    context->SetApplicationInfo(applicationInfo);
    HILOG_DEBUG("bundleName is %{public}s, moduleName is %{public}s",
        formJsInfo.bundleName.c_str(), formJsInfo.moduleName.c_str());

    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    contextsMapForModuleName_.emplace(GenerateContextKey(formJsInfo), context);
    return context;
}

void FormRenderRecord::SetConfiguration(const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    configuration_ = config;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::GetFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    HILOG_INFO("Get formRendererGroup.");
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto key = formJsInfo.formId;
    auto iter = formRendererGroupMap_.find(key);
    if (iter != formRendererGroupMap_.end()) {
        return iter->second;
    }

    auto formRendererGroup = CreateFormRendererGroupLock(formJsInfo, context, runtime);
    if (formRendererGroup != nullptr) {
        HILOG_INFO("formRendererGroupMap emplace formId:%{public}s", std::to_string(key).c_str());
        formRendererGroupMap_.emplace(key, formRendererGroup);
    }
    return formRendererGroup;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    HILOG_INFO("Create formRendererGroup.");
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

void FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Update record in js thread.");
    if (runtime_ == nullptr && !CreateRuntime(formJsInfo)) {
        HILOG_ERROR("Create runtime failed.");
        return;
    }
    auto context = GetContext(formJsInfo, want);
    if (context == nullptr) {
        HILOG_ERROR("Create Context failed.");
        return;
    }
    auto renderType = want.GetIntParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    HILOG_INFO("renderType is %{public}d.", renderType);
    if (renderType == Constants::RENDER_FORM) {
        auto formRendererGroup = GetFormRendererGroup(formJsInfo, context, runtime_);
        if (formRendererGroup == nullptr) {
            HILOG_ERROR("Create formRendererGroup failed.");
            return;
        }
        formRendererGroup->AddForm(want, formJsInfo);
        HILOG_INFO("AddForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    } else {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        if (auto search = formRendererGroupMap_.find(formJsInfo.formId);
            search != formRendererGroupMap_.end()) {
            auto group = search->second;
            group->UpdateForm(formJsInfo);
        }
        HILOG_INFO("UpdateForm formId:%{public}s", std::to_string(formJsInfo.formId).c_str());
    }
    return;
}

bool FormRenderRecord::HandleDeleteInJsThread(int64_t formId, const std::string &compId)
{
    HILOG_INFO("Delete some resources in js thread.");
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_INFO("HandleDeleteInJsThread failed. FormRendererGroup was not founded.");
            return false;
        }
        if (!search->second) {
            HILOG_INFO("HandleDeleteInJsThread failed. FormRendererGroup was founded but is null.");
            return false;
        }
        if (!compId.empty()) {
            search->second->DeleteForm(compId);
            HILOG_INFO("HandleDeleteInJsThread compid is %{public}s", compId.c_str());
            return false;
        }
        search->second->DeleteForm();
        formRendererGroupMap_.erase(formId);
    }
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    hostsMapForFormId_.erase(formId);
    return true;
}

void FormRenderRecord::HandleDestroyInJsThread()
{
    HILOG_INFO("FormRenderService is exiting, destroy some resources in js thread.");
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    formRendererGroupMap_.clear();
    runtime_.reset();
}

inline std::string FormRenderRecord::GenerateContextKey(const FormJsInfo &formJsInfo)
{
    return formJsInfo.bundleName + ":" +  formJsInfo.moduleName;
}

int32_t FormRenderRecord::ReloadFormRecord(const std::vector<int64_t> &&formIds, const Want &want)
{
    HILOG_INFO("Reload form record");
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, ids = std::forward<decltype(formIds)>(formIds), want]() {
        HILOG_DEBUG("HandleReloadFormRecord begin.");
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleReloadFormRecord(std::move(ids), want);
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return RELOAD_FORM_FAILED;
    }
    eventHandler_->PostTask(task);
    return ERR_OK;
}

int32_t FormRenderRecord::HandleReloadFormRecord(const std::vector<int64_t> &&formIds, const Want &want)
{
    HILOG_INFO("Reload record in js thread.");
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    for (auto formId : formIds) {
        auto search = formRendererGroupMap_.find(formId);
        if (search == formRendererGroupMap_.end()) {
            HILOG_ERROR("HandleReloadFormRecord failed. FormRendererGroup was not found.");
            continue;
        }
        auto group = search->second;
        if (!group) {
            HILOG_ERROR("HandleReloadFormRecord failed. FormRendererGroup is null.");
            continue;
        }
        group->ReloadForm();
    }
    return ERR_OK;
}

void FormRenderRecord::UpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    HILOG_INFO("UpdateConfiguration begin");
    if (!config) {
        HILOG_ERROR("UpdateConfiguration failed due to config is nullptr");
        return;
    }

    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, config]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleUpdateConfiguration(config);
    };
    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(task);
}

void FormRenderRecord::HandleUpdateConfiguration(
    const std::shared_ptr<OHOS::AppExecFwk::Configuration>& config)
{
    HILOG_INFO("HandleUpdateConfiguration begin.");
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    for (auto iter = formRendererGroupMap_.begin(); iter != formRendererGroupMap_.end(); ++iter) {
        if (iter->second) {
            iter->second->UpdateConfiguration(config);
        }
    }
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
