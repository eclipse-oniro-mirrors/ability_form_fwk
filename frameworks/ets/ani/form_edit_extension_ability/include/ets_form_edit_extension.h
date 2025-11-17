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

#ifndef OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_H

#include "form_edit_extension.h"
#include "ets_form_edit_extension_impl.h"
#include "configuration.h"
#include "ets_ui_extension_base.h"
#include <unordered_set>

namespace OHOS {
namespace AbilityRuntime {

/**
 * @brief Basic form edit extension components.
 */
class EtsFormEditExtension : public FormEditExtension, public std::enable_shared_from_this<EtsFormEditExtension> {
public:
    explicit EtsFormEditExtension(const std::unique_ptr<Runtime> &etsRuntime);
    ~EtsFormEditExtension() override = default;

    /**
     * @brief Init the form edit extension.
     *
     * @param record the form edit extension record.
     * @param application the application info.
     * @param handler the form edit extension handler.
     * @param token the remote token.
     */
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Create EtsFormEditExtension.
     *
     * @param runtime The runtime.
     * @return The EtsFormEditExtension instance.
     */
    static EtsFormEditExtension *Create(const std::unique_ptr<Runtime> &etsRuntime);

private:
    std::shared_ptr<EtsFormEditExtensionImpl> impl_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_H