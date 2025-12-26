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

#include "js_live_form_extension.h"
#include "hitrace_meter.h"
#include "js_ui_extension_base.h"
#include "fms_log_wrapper.h"
#include "js_live_form_extension_context.h"
#include "js_live_form_extension_impl.h"

namespace OHOS {
namespace AbilityRuntime {
JsLiveFormExtension *JsLiveFormExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new JsLiveFormExtension(runtime);
}

JsLiveFormExtension::JsLiveFormExtension(const std::unique_ptr<Runtime> &runtime)
{
    impl_ = std::make_shared<JsLiveFormExtensionImpl>(runtime);
    SetUIExtensionBaseImpl(impl_);
}

void JsLiveFormExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
    std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_DEBUG("Begin init live form extension");
    if (record == nullptr) {
        HILOG_ERROR("null record");
        return;
    }

    auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        HILOG_ERROR("null appContext");
        return;
    }

    if (impl_ == nullptr) {
        HILOG_ERROR("null impl_");
        return;
    }

    std::shared_ptr<LiveFormExtensionContext> context = std::make_shared<LiveFormExtensionContext>();
    context->SetToken(token);
    context->SetApplicationInfo(appContext->GetApplicationInfo());
    context->SetResourceManager(appContext->GetResourceManager());
    context->SetParentContext(appContext);

    auto abilityInfo = record->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        HILOG_ERROR("null abilityInfo");
        return;
    }
    context->SetAbilityInfo(abilityInfo);
    context->InitHapModuleInfo(abilityInfo);
    context->SetConfiguration(appContext->GetConfiguration());
    if (abilityInfo->applicationInfo.multiProjects) {
        std::shared_ptr<Context> moduleContext = context->CreateModuleContext(abilityInfo->moduleName);
        if (moduleContext != nullptr) {
            auto rm = moduleContext->GetResourceManager();
            context->SetResourceManager(rm);
        }
    }

    Extension::Init(record, application, handler, token);
    impl_->SetContext(context);
    impl_->SetAbilityInfo(Extension::abilityInfo_);
    auto extensionCommon = impl_->Init(record, application, handler, token);
    ExtensionBase<LiveFormExtensionContext>::SetExtensionCommon(extensionCommon);
}
} // namespace AbilityRuntime
} // namespace OHOS