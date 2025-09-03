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

#include "ets_form_edit_extension_impl.h"
#include "hilog_tag_wrapper.h"
#include "ets_form_edit_extension_context.h"
#include "ets_ui_extension_content_session.h"
#include "ani_common_want.h"

namespace OHOS {
namespace AbilityRuntime {

EtsFormEditExtensionImpl::EtsFormEditExtensionImpl(const std::unique_ptr<Runtime> &etsRuntime)
    : EtsUIExtensionBase(etsRuntime)
{}

void EtsFormEditExtensionImpl::BindContext()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "BindContext");
    if (etsObj_ == nullptr) {
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context_");
        return;
    }
    ani_object contextObj = EtsFormEditExtensionContext::CreateEtsFormEditExtensionContext(env, context_);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null contextObj");
        return;
    }
    ani_field contextField;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_GetField context failed");
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        TAG_LOGD(AAFwkTag::UI_EXT, "Object_SetField_Ref contextObj failed");
    }
    context_->Bind(etsRuntime_, &contextRef);
    TAG_LOGI(AAFwkTag::UI_EXT, "BindContext end");
}
} // namespace AbilityRuntime
} // namespace OHOS