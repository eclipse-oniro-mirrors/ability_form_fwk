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

#ifndef OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_CONTEXT_H

#include "ui_extension_context.h"
namespace OHOS {
namespace AbilityRuntime {

enum class FormEditErrorCode {
    // success
    ERROR_OK = 0,

    // param error
    ERROR_CODE_PARAM_ERROR = 401,

    // internal error
    ERROR_CODE_INTERNAL_ERROR = 16501000
};

class FormEditExtensionContext : public UIExtensionContext {
public:
    FormEditExtensionContext() = default;

    virtual ~FormEditExtensionContext() = default;

    void SetWant(const std::shared_ptr<AAFwk::Want> &want);

    static const size_t CONTEXT_TYPE_ID;

    ErrCode StartAbilityByFms(const AAFwk::Want &want);

    ErrCode StartUIAbilityByFms(const AAFwk::Want &want);

private:
    std::shared_ptr<AAFwk::Want> want_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_FORM_EDIT_EXTENSION_CONTEXT_H