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

#ifndef OHOS_FORM_FWK_RESOURCE_OBSERVER_H
#define OHOS_FORM_FWK_RESOURCE_OBSERVER_H

#include <string>

#include "configuration_observer_stub.h"

namespace OHOS {
namespace AppExecFwk {
class FormFwkResourceObserver : public ConfigurationObserverStub {
public:
    FormFwkResourceObserver();

    virtual ~FormFwkResourceObserver() override;

    void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;
private:
    std::string colorMode_;
    std::string language_;
};
} // AppExecFwk
} // OHOS
#endif // OHOS_FORM_FWK_RESOURCE_OBSERVER_H
