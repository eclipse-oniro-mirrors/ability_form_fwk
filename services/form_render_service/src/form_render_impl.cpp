/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "js_context_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "service_extension.h"
#include "runtime.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using namespace AbilityRuntime;

sptr<FormRenderImpl> FormRenderImpl::instance_;

static OHOS::AbilityRuntime::ServiceExtension *FormRenderServiceCreator(const std::unique_ptr<Runtime> &runtime)
{
    HILOG_DEBUG("Create FormRenderServiceExtension");
    return  FormRenderServiceExtension::Create(runtime);
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
    HILOG_INFO("%{public}s called.", __func__);
    return ERR_OK;
}

int32_t FormRenderImpl::AddForm(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Kee Init form");
    return ERR_OK;
}

int32_t FormRenderImpl::DeleteRenderForm(
    const int64_t &formId, const Want &want, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("%{public}s called.", __func__);
    return ERR_OK;
}


int32_t FormRenderImpl::UpdateForm(const FormJsInfo &formJsInfo, const Want &want)
{
    HILOG_INFO("Raul update form");
    return ERR_OK;
}

void FormRenderImpl::SetRuntime(AbilityRuntime::Runtime& runtime)
{
    HILOG_INFO("%{public}s called.", __func__);
}

void FormRenderImpl::OnActionEvent(const std::string& action) const
{
    HILOG_INFO("OnActionEvent: action: %{public}s", action.c_str());
}

std::shared_ptr<Runtime> FormRenderImpl::ObtainRuntime(const FormJsInfo &formJsInfo,
    const std::shared_ptr<EventRunner> runner)
{
    return nullptr;
}

std::shared_ptr<Runtime> FormRenderImpl::CreateRuntimeLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<EventRunner> runner)
{
    return nullptr;
}

std::shared_ptr<Context> FormRenderImpl::ObtainContext(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Runtime> &runtime)
{
    return nullptr;
}

std::shared_ptr<Context> FormRenderImpl::CreateContextLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Runtime> &runtime)
{
    return nullptr;
}

std::shared_ptr<Ace::UIContent> FormRenderImpl::ObtainUIContent(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime)
{
    return nullptr;
}

std::shared_ptr<Ace::UIContent> FormRenderImpl::CreateUIContentLock(const FormJsInfo &formJsInfo,
    const std::shared_ptr<Context> &context, const std::shared_ptr<Runtime> &runtime)
{
    return nullptr;
}

std::shared_ptr<EventRunner> FormRenderImpl::ObtainEventRunner(const FormJsInfo &formJsInfo)
{
    return nullptr;
}

std::shared_ptr<EventRunner> FormRenderImpl::CreateEventRunnerLock(const FormJsInfo &formJsInfo)
{
    return nullptr;
}
} // namespace FormRender
} // namespace AppExecFwk
} // namespace OHOS
