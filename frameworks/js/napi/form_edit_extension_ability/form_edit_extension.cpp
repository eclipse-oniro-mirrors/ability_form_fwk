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

#include "form_edit_extension.h"
#include "hilog_tag_wrapper.h"
#include "js_form_edit_extension.h"
#include "runtime.h"
#include "form_edit_extension_context.h"
namespace OHOS {
namespace AbilityRuntime {
FormEditExtension::FormEditExtension()
{
    TAG_LOGI(AAFwkTag::FORM_EDIT_EXT, "call");
}

FormEditExtension *FormEditExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    if (!runtime) {
        return new FormEditExtension();
    }
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsFormEditExtension::Create(runtime);
        default:
            return new FormEditExtension();
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
