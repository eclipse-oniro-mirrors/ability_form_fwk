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

#ifndef OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_H
#define OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_H

#include "configuration.h"
#include "js_ui_extension_base.h"
#include "live_form_extension.h"

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class JsRuntime;
class JsLiveFormExtensionImpl;

/**
 * @brief Basic live form extension components.
 */
class JsLiveFormExtension : public LiveFormExtension,
                            public std::enable_shared_from_this<JsLiveFormExtension> {
public:
    explicit JsLiveFormExtension(const std::unique_ptr<Runtime> &runtime);

    ~JsLiveFormExtension() override = default;

    /**
     * @brief Init the live form extension.
     *
     * @param record the live form extension record.
     * @param application the application info.
     * @param handler the live form extension handler.
     * @param token the remote token.
     */
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Create JsLiveFormExtension.
     *
     * @param runtime The runtime.
     * @return The JsLiveFormExtension instance.
     */
    static JsLiveFormExtension *Create(const std::unique_ptr<Runtime> &runtime);

private:
    std::shared_ptr<JsLiveFormExtensionImpl> impl_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_JS_LIVE_FORM_EXTENSION_H