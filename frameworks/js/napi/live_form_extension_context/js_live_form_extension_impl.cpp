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

#include "js_live_form_extension_impl.h"
#include "js_ui_extension_content_session.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_want.h"
#include "fms_log_wrapper.h"
#include "js_live_form_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
} // namespace

napi_value AttachUIExtensionContext(napi_env env, void *value, void *)
{
    HILOG_DEBUG("called");
    if (value == nullptr) {
        HILOG_ERROR("Invalid param value");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<LiveFormExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        HILOG_ERROR("Invalid context");
        return nullptr;
    }
    napi_value object = JsLiveFormExtensionContext::CreateJsLiveFormExtensionContext(env, ptr);
    auto contextRef =
        JsRuntime::LoadSystemModuleByEngine(env, "application.LiveFormExtensionContext", &object, ARGC_ONE);
    if (contextRef == nullptr) {
        HILOG_ERROR("Fail to load module");
        return nullptr;
    }
    auto contextObj = contextRef->GetNapiValue();
    if (contextObj == nullptr) {
        HILOG_ERROR("Load context error");
        return nullptr;
    }
    napi_coerce_to_native_binding_object(env, contextObj, DetachCallbackFunc, AttachUIExtensionContext, value,
                                        nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<LiveFormExtensionContext>(ptr);
    napi_status status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            HILOG_DEBUG("Finalizer called");
            if (data == nullptr) {
                HILOG_ERROR("Finalizer for weak_ptr is nullptr");
                return;
            }
            delete static_cast<std::weak_ptr<LiveFormExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        HILOG_ERROR("napi_wrap Failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return contextObj;
}

JsLiveFormExtensionImpl::JsLiveFormExtensionImpl(const std::unique_ptr<Runtime> &runtime)
    : JsUIExtensionBase(runtime)
{}

void JsLiveFormExtensionImpl::BindContext()
{
    HandleScope handleScope(jsRuntime_);
    if (jsObj_ == nullptr) {
        HILOG_ERROR("null jsObj_");
        return;
    }

    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value obj = jsObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        HILOG_ERROR("obj is not object");
        return;
    }
    if (context_ == nullptr) {
        HILOG_ERROR("null Context");
        return;
    }
    HILOG_DEBUG("BindContext CreateJsLiveFormExtensionContext");
    napi_value contextObj = JsLiveFormExtensionContext::CreateJsLiveFormExtensionContext(env, context_);
    if (contextObj == nullptr) {
        HILOG_ERROR("Create js ui extension context error");
        return;
    }

    shellContextRef_ =
        JsRuntime::LoadSystemModuleByEngine(env, "application.LiveFormExtensionContext", &contextObj, ARGC_ONE);
    if (shellContextRef_ == nullptr) {
        HILOG_ERROR("Fail to get loadSystemModuleByEngine");
        return;
    }
    contextObj = shellContextRef_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        HILOG_ERROR("Fail to get context native object");
        return;
    }

    auto workContext = new (std::nothrow) std::weak_ptr<LiveFormExtensionContext>(context_);
    napi_coerce_to_native_binding_object(env, contextObj, DetachCallbackFunc, AttachUIExtensionContext,
        workContext, nullptr);
    context_->Bind(jsRuntime_, shellContextRef_.get());
    napi_set_named_property(env, obj, "context", contextObj);
    napi_status status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            if (data == nullptr) {
                HILOG_ERROR("Finalizer for weak_ptr is nullptr");
                return;
            }
            delete static_cast<std::weak_ptr<LiveFormExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        HILOG_ERROR("napi_wrap Failed: %{public}d", status);
        delete workContext;
    }

    HILOG_DEBUG("Bind context end");
}
} // namespace AbilityRuntime
} // namespace OHOS