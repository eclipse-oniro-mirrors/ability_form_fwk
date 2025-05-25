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

#ifndef OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_H

#include "ui_extension_base.h"
#include "form_edit_extension_context.h"
namespace OHOS {
namespace AbilityRuntime {
class FormEditExtensionContext;
class Runtime;
/**
 * @brief FormEdit Extension components.
 */
class FormEditExtension : public UIExtensionBase<FormEditExtensionContext>,
                          public std::enable_shared_from_this<FormEditExtension> {
public:
    explicit FormEditExtension();
    virtual ~FormEditExtension() = default;

    /**
     * @brief Create FormEditExtension UI extension.
     *
     * @param runtime The runtime.
     * @return The FormEdit Extension instance.
     */
    static FormEditExtension *Create(const std::unique_ptr<Runtime> &runtime);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_H
