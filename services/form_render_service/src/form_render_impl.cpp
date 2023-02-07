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
#include "form_mgr_errors.h"
#include "form_supply_proxy.h"
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
        HILOG_WARN("%{public}s warn, IFormSupply is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    HILOG_DEBUG("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));

    int32_t result = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
        if (auto search = formRendererGroupMap_.find(formJsInfo.formId); search == formRendererGroupMap_.end()) {
            result = AddForm(formJsInfo, want);
            if (result != ERR_OK) {
                HILOG_ERROR("Add form failed.");
            }
        } else {
            result = UpdateForm(formJsInfo, want);
        }
    }
    formSupplyClient->OnRenderTaskDone(formJsInfo.formId, want);
    return result;
}

int32_t FormRenderImpl::AddForm(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Obtain EventRunner");
    auto runner = ObtainEventRunner(formJsInfo);
    if (runner == nullptr) {
        HILOG_ERROR("Obtain runtime failed.");
        return RENDER_FORM_FAILED;
    }

    auto actionEventHandler = [&](const std::string& action) {
        OnActionEvent(action);
    };

    auto task = [this, formJsInfo, want, actionEventHandler, runner]() {
        HILOG_INFO("Obtain Runtime");
        auto runtime = this->ObtainRuntime(formJsInfo, runner);
        if (runtime == nullptr) {
            HILOG_ERROR("Obtain runtime failed.");
            return;
        }

        HILOG_INFO("Obtain context");
        auto context = this->ObtainContext(formJsInfo, runtime);
        if (context == nullptr) {
            HILOG_ERROR("Obtain context failed.");
            return;
        }

        {
            std::lock_guard<std::mutex> lock(this->formRendererGroupMutex_);
            if (auto search = this->formRendererGroupMap_.find(formJsInfo.formId);
                search != this->formRendererGroupMap_.end()) {
                auto group = search->second;
                group->UpdateForm(formJsInfo);
                return;
            }
        }

        HILOG_INFO("Obtain FormRenderGroup");
        auto formRendererGroup = this->ObtainFormRendererGroup(formJsInfo, context, runtime);
        if (runtime == nullptr) {
            HILOG_ERROR("Create formRendererGroup failed.");
            return;
        }
        formRendererGroup->AddForm(want, formJsInfo);
        HILOG_INFO("Kee Ace::FormRendererGroup::task over");
    };

    std::shared_ptr<EventHandler> handler = nullptr;
    if (auto search = eventHandlerMap_.find(formJsInfo.bundleName); search != eventHandlerMap_.end()) {
        handler = search->second;
    }
    if (handler == nullptr) {
        HILOG_ERROR("event handler is nullptr.");
        return RENDER_FORM_FAILED;
    }

    handler->PostTask(task);
    HILOG_ERROR("Kee Ace::FormRendererGroup::OK");
    return ERR_OK;
}

int32_t FormRenderImpl::StopRenderingForm(int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s called.", __func__);
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    if (formSupplyClient == nullptr) {
        HILOG_WARN("%{public}s warn, IFormSupply is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    HILOG_DEBUG("%{public}s come, connectId: %{public}d.", __func__,
        want.GetIntParam(Constants::FORM_CONNECT_ID, 0L));

    formSupplyClient->OnStopRenderingTaskDone(formId, want);
    return ERR_OK;
}

int32_t FormRenderImpl::UpdateForm(const FormJsInfo &formJsInfo, const Want &want)
{
    // start render task
    std::shared_ptr<Ace::FormRendererGroup> sFormRendererGroup = nullptr;
    if (auto search = formRendererGroupMap_.find(formJsInfo.formId); search != formRendererGroupMap_.end()) {
        sFormRendererGroup = search->second;
    }

    std::shared_ptr<EventRunner> runner = nullptr;
    auto key = formJsInfo.bundleName;
    if (auto search = eventRunnerMap_.find(key); search != eventRunnerMap_.end()) {
        runner = search->second;
    }
    std::weak_ptr<Ace::FormRendererGroup> wFormRendererGroup = sFormRendererGroup;
    auto task = [wFormRendererGroup, formJsInfo, want]() {
        HILOG_INFO("Kee Ace::FormRendererGroup::task, data = %{public}s", formJsInfo.formData.c_str());
        auto formRendererGroup = wFormRendererGroup.lock();
        formRendererGroup->UpdateForm(formJsInfo);
        HILOG_INFO("Kee Ace::FormRendererGroup::task over");
    };

    auto handler = std::make_shared<EventHandler>(runner);
    if (handler) {
        handler->PostTask(task);
    }

    HILOG_ERROR("Ace FormRendererGroup OK");
    return ERR_OK;
}

std::shared_ptr<Runtime> FormRenderImpl::ObtainRuntime(const FormJsInfo &formJsInfo,
    const std::shared_ptr<EventRunner> runner)
{
    std::lock_guard<std::mutex> lock(runTimeMutex_);
    auto key = formJsInfo.bundleName;
    if (auto search = runTimeMap_.find(key); search != runTimeMap_.end()) {
        return search->second;
    }
    auto runtime = CreateRuntimeLock(formJsInfo, runner);
    if (runtime != nullptr) {
        runTimeMap_.emplace(key, runtime);
    }
    return runtime;
}

std::shared_ptr<Runtime> FormRenderImpl::CreateRuntimeLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<EventRunner> runner)
{
    AbilityRuntime::Runtime::Options options;
    options.bundleName = formJsInfo.bundleName;
    options.codePath = Constants::LOCAL_CODE_PATH;
    BundleInfo bundleInfo;
    options.eventRunner = runner;
    options.hapPath = formJsInfo.jsFormCodePath;
    options.loadAce = true;
    options.isBundle = true;
    options.isUnique = true;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    if (!runtime) {
        HILOG_ERROR("create runtime Failed!");
        return nullptr;
    }
    return runtime;
}

std::shared_ptr<Context> FormRenderImpl::ObtainContext(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Runtime> &runtime)
{
    std::lock_guard<std::mutex> lock(contextMutex_);
    auto key = formJsInfo.bundleName + formJsInfo.moduleName;
    if (auto search = contextMap_.find(key); search != contextMap_.end()) {
        return search->second;
    }
    auto context = CreateContextLock(formJsInfo, runtime);
    if (context != nullptr) {
        contextMap_.emplace(key, context);
    }
    return context;
}

std::shared_ptr<Context> FormRenderImpl::CreateContextLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Runtime> &runtime)
{
    auto context = std::make_shared<AbilityRuntime::ContextImpl>();
    if (!context) {
        HILOG_ERROR("construct context failed!");
        return nullptr;
    }
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = formJsInfo.moduleName;
    hapModuleInfo.hapPath = formJsInfo.jsFormCodePath;
    context->InitHapModuleInfo(hapModuleInfo);
    auto applicationInfo = std::make_shared<AppExecFwk::ApplicationInfo>();
    applicationInfo->bundleName = formJsInfo.bundleName;
    context->SetApplicationInfo(applicationInfo);
    return context;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderImpl::ObtainFormRendererGroup(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime)
{
    std::lock_guard<std::mutex> lock(formRendererGroupMutex_);
    auto key = formJsInfo.formId;
    if (auto search = formRendererGroupMap_.find(key); search != formRendererGroupMap_.end()) {
        return search->second;
    }
    auto formRendererGroup = CreateFormRendererGroupLock(formJsInfo, context, runtime);
    if (formRendererGroup != nullptr) {
        formRendererGroupMap_.emplace(key, formRendererGroup);
    }
    return formRendererGroup;
}

std::shared_ptr<Ace::FormRendererGroup> FormRenderImpl::CreateFormRendererGroupLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime)
{
    auto& nativeEngine = (static_cast<AbilityRuntime::JsRuntime&>(*runtime.get())).GetNativeEngine();
    HILOG_ERROR("Ace formRendererGroup create context_ = %{public}p nativeEngine = %{public}p",
        context.get(), &nativeEngine);
    auto formRendererGroup = Ace::FormRendererGroup::Create(context, runtime);
    if (formRendererGroup == nullptr) {
        HILOG_ERROR("Create formRendererGroup failed");
        return nullptr;
    }
    return formRendererGroup;
}

std::shared_ptr<EventRunner> FormRenderImpl::ObtainEventRunner(const FormJsInfo &formJsInfo)
{
    std::lock_guard<std::mutex> lock(eventRunnerMutex_);
    auto key = formJsInfo.bundleName;
    if (auto search = eventRunnerMap_.find(key); search != eventRunnerMap_.end()) {
        return search->second;
    }
    auto eventRunner = CreateEventRunnerLock(formJsInfo);
    auto eventHandler = std::make_shared<EventHandler>(eventRunner);
    if (eventRunner != nullptr) {
        eventRunnerMap_.emplace(key, eventRunner);
        eventHandlerMap_.emplace(key, eventHandler);
    }
    return eventRunner;
}

std::shared_ptr<EventRunner> FormRenderImpl::CreateEventRunnerLock(const FormJsInfo &formJsInfo)
{
    std::shared_ptr<EventRunner> runner = EventRunner::Create(formJsInfo.bundleName);
    if (runner == nullptr) {
        HILOG_ERROR("create runner Failed.");
        return nullptr;
    }
    return runner;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
