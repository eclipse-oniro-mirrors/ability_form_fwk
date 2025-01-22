/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_JS_FORM_EDIT_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_JS_FORM_EDIT_EXTENSION_H

#include "form_edit_extension.h"
#include "configuration.h"
#include "js_ui_extension_base.h"
#include <unordered_set>

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class JsRuntime;
class JsFormEditExtensionImpl;

/**
 * @brief Basic form edit extension components.
 */
class JsFormEditExtension : public FormEditExtension, public std::enable_shared_from_this<JsFormEditExtension> {
public:
    explicit JsFormEditExtension(const std::unique_ptr<Runtime> &runtime);
    virtual ~JsFormEditExtension() override = default;

/**
     * @brief Init the photo editor extension.
     *
     * @param record the photo editor extension record.
     * @param application the application info.
     * @param handler the photo editor extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
                      const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
                      std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Create JsFormEditExtension.
     *
     * @param runtime The runtime.
     * @return The JsFormEditExtension instance.
     */
    static JsFormEditExtension *Create(const std::unique_ptr<Runtime> &runtime);

private:
    std::shared_ptr<JsFormEditExtensionImpl> impl_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_FORM_EDIT_EXTENSION_H