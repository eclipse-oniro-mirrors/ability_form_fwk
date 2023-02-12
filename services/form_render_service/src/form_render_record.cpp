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

#include "form_constants.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
constexpr int32_t RENDER_FORM_FAILED = -1;
std::shared_ptr<FormRenderRecord> FormRenderRecord::Create(const std::string &bundleName, int32_t uid)
{
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
    const std::string &bundleName, int32_t uid) : bundleName_(bundleName), uid_(uid) {}

bool FormRenderRecord::HandleHostDied(const sptr<IRemoteObject> hostRemoteObj)
{
    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    for (auto item = hostsMapForFormId_.begin(); item != hostsMapForFormId_.end();) {
        std::unordered_set<sptr<IRemoteObject>, RemoteObjHash> &hosts = item->second;
        hosts.erase(hostRemoteObj);
        if (hosts.empty()) {
            item = hostsMapForFormId_.erase(item);
        } else {
            ++item;
        }
    }
    return hostsMapForFormId_.empty();
}

bool FormRenderRecord::CreateEventHandler(const std::string &bundleName)
{
    if (eventHandler_) {
        return true;
    }

    // Create event runner
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
    // Some resources need to be initialized in a JS thread
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formJsInfo, want]() {
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

    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    auto item = hostsMapForFormId_.find(formJsInfo.formId);
    if (item == hostsMapForFormId_.end()) {
        hostsMapForFormId_.emplace(formJsInfo.formId, std::unordered_set<sptr<IRemoteObject>, RemoteObjHash>());
        item = hostsMapForFormId_.begin();
    }
    item->second.emplace(hostRemoteObj);
    return ERR_OK;
}

int32_t FormRenderRecord::DeleteRenderRecord(int64_t formId, const Want &want, const sptr<IRemoteObject> hostRemoteObj)
{
    // Some resources need to be initialized in a JS thread
    std::weak_ptr<FormRenderRecord> thisWeakPtr(shared_from_this());
    auto task = [thisWeakPtr, formId, want]() {
        auto renderRecord = thisWeakPtr.lock();
        if (renderRecord == nullptr) {
            HILOG_ERROR("renderRecord is nullptr.");
            return;
        }
        renderRecord->HandleDeleteInJsThread(formId, want);
    };

    if (eventHandler_ == nullptr) {
        HILOG_ERROR("eventHandler_ is nullptr");
        return RENDER_FORM_FAILED;
    }
    eventHandler_->PostTask(task);

    std::lock_guard<std::mutex> lock(hostsMapMutex_);
    hostsMapForFormId_.erase(formId);
    if (hostsMapForFormId_.empty()) {
        return RENDER_FORM_FAILED;
    }
    return ERR_OK;
}

int32_t FormRenderRecord::GetUid() const
{
    return uid_;
}

bool FormRenderRecord::CreateRuntime(const FormJsInfo &formJsInfo)
{
    if (runtime_) {
        return true;
    }

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
        auto item = contextsMapForModuleName_.find(formJsInfo.moduleName);
        if (item != contextsMapForModuleName_.end()) {
            return item->second;
        }
    }

    return CreateContext(formJsInfo, want);
}

std::shared_ptr<AbilityRuntime::Context> FormRenderRecord::CreateContext(const FormJsInfo &formJsInfo, const Want &want)
{
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (context == nullptr) {
        HILOG_ERROR("Create context failed!");
        return nullptr;
    }
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = formJsInfo.moduleName;
    hapModuleInfo.hapPath = formJsInfo.jsFormCodePath;
    hapModuleInfo.compileMode = static_cast<CompileMode>(want.GetIntParam(Constants::FORM_COMPILE_MODE_KEY,
        static_cast<int32_t>(CompileMode::ES_MODULE)));
    context->InitHapModuleInfo(hapModuleInfo);
    auto applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = formJsInfo.bundleName;
    context->SetApplicationInfo(applicationInfo);
    HILOG_DEBUG("bundleName is %{public}s, moduleName is %{public}s",
        formJsInfo.bundleName.c_str(), formJsInfo.moduleName.c_str());

    std::lock_guard<std::mutex> lock(contextsMapMutex_);
    contextsMapForModuleName_.emplace(formJsInfo.moduleName, context);
    return context;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::GetFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto key = formJsInfo.formId;
    auto formRendererGroup = CreateFormRendererGroupLock(formJsInfo, context, runtime);
    if (formRendererGroup != nullptr) {
        formRendererGroupMap_.emplace(key, formRendererGroup);
    }
    return formRendererGroup;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderRecord::CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<AbilityRuntime::Context> &context, const std::shared_ptr<AbilityRuntime::Runtime> &runtime)
{
    auto& nativeEngine = (static_cast<AbilityRuntime::JsRuntime&>(*runtime.get())).GetNativeEngine();
    HILOG_INFO("Ace formRendererGroup create context_ = %{public}p nativeEngine = %{public}p",
        context.get(), &nativeEngine);
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

void FormRenderRecord::HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want)
{
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
        auto formRendererGroup = this->GetFormRendererGroup(formJsInfo, context, runtime_);
        if (formRendererGroup == nullptr) {
            HILOG_ERROR("Create formRendererGroup failed.");
            return;
        }
        formRendererGroup->AddForm(want, formJsInfo);
    } else {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        if (auto search = this->formRendererGroupMap_.find(formJsInfo.formId);
            search != this->formRendererGroupMap_.end()) {
            auto group = search->second;
            group->UpdateForm(formJsInfo);
        }
    }
    return;
}

void FormRenderRecord::HandleDeleteInJsThread(int64_t formId, const Want &want)
{
    {
        auto compId = want.GetStringParam("ohos.extra.param.key.form_comp_id");
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        if (auto search = this->formRendererGroupMap_.find(formId);
            search != this->formRendererGroupMap_.end()) {
            auto group = search->second;
            group->DeleteForm(compId);
            return;
        }
    }
    HILOG_ERROR("HandleDeleteInJsThread failed. FormRendererGroup was not found.");
    return;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
