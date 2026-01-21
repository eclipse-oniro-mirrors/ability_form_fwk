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

#include "js_form_edit_extension_impl.h"
#include "hilog_tag_wrapper.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "js_form_edit_extension_context.h"
#include "js_ui_extension_content_session.h"
#include "napi_common_want.h"

namespace OHOS {
namespace AbilityRuntime {

namespace {
constexpr size_t ARGC_ONE = 1;
} // namespace

napi_value AttachUIExtensionContext(napi_env env, void *value, void *)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    if (value == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid param value");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<FormEditExtensionContext> *>(value)->lock();
    if (ptr == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid context");
        return nullptr;
    }
    napi_value object = JsFormEditExtensionContext::CreateJsFormEditExtensionContext(env, ptr);
    auto contextRef =
        JsRuntime::LoadSystemModuleByEngine(env, "application.FormEditExtensionContext", &object, ARGC_ONE);
    if (contextRef == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Fail to load module");
        return nullptr;
    }
    auto contextObj = contextRef->GetNapiValue();
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Load context error");
        return nullptr;
    }
    napi_coerce_to_native_binding_object(env, contextObj, DetachCallbackFunc, AttachUIExtensionContext, value, nullptr);
    auto workContext = new (std::nothrow) std::weak_ptr<FormEditExtensionContext>(ptr);
    napi_status status = napi_wrap(
        env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::UI_EXT, "Finalizer called");
            if (data == nullptr) {
                TAG_LOGE(AAFwkTag::UI_EXT, "Finalizer for weak_ptr is nullptr");
                return;
            }
            delete static_cast<std::weak_ptr<FormEditExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "napi_wrap Failed: %{public}d", status);
        delete workContext;
        return nullptr;
    }

    return contextObj;
}

JsFormEditExtensionImpl::JsFormEditExtensionImpl(const std::unique_ptr<Runtime> &runtime)
    : JsUIExtensionBase(runtime)
{}

void JsFormEditExtensionImpl::BindContext()
{
    HandleScope handleScope(jsRuntime_);
    if (jsObj_ == nullptr) {
        return;
    }
    napi_env env = jsRuntime_.GetNapiEnv();
    napi_value obj = jsObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "obj is not object");
        return;
    }
    if (context_ == nullptr) {
        return;
    }
    napi_value contextObj = JsFormEditExtensionContext::CreateJsFormEditExtensionContext(env, context_);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Create js ui extension context error");
        return;
    }
    shellContextRef_ =
        JsRuntime::LoadSystemModuleByEngine(env, "application.FormEditExtensionContext", &contextObj, ARGC_ONE);
    if (shellContextRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Fail to get loadSystemModuleByEngine");
        return;
    }
    contextObj = shellContextRef_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Fail to get context native object");
        return;
    }
    auto workContext = std::make_shared(context_);
    napi_coerce_to_native_binding_object(env, contextObj, DetachCallbackFunc, AttachUIExtensionContext, workContext,
                                         nullptr);
    context_->Bind(jsRuntime_, shellContextRef_.get());
    napi_set_named_property(env, obj, "context", contextObj);
    napi_status status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void *data, void *) {
            if (data == nullptr) {
                TAG_LOGE(AAFwkTag::UI_EXT, "Finalizer for weak_ptr is nullptr");
                return;
            }
            delete static_cast<std::weak_ptr<FormEditExtensionContext> *>(data);
        }, nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "napi_wrap Failed: %{public}d", status);
        delete workContext;
        return;
    }
}

} // namespace AbilityRuntime
} // namespace OHOS