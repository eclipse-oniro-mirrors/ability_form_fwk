/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
 * Stub header for FormProviderAcquireErrorHandler used in unit testing.
 */

#ifndef OHOS_FORM_FWK_MOCK_FORM_PROVIDER_ACQUIRE_ERROR_HANDLER_H
#define OHOS_FORM_FWK_MOCK_FORM_PROVIDER_ACQUIRE_ERROR_HANDLER_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "iremote_object.h"
#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {

class MockFormProviderAcquireErrorHandler {
public:
    static std::shared_ptr<MockFormProviderAcquireErrorHandler> obj;
    MockFormProviderAcquireErrorHandler() = default;
    virtual ~MockFormProviderAcquireErrorHandler() = default;

    MOCK_METHOD2(HandleDisconnectError, bool(int64_t formId, const sptr<FormAbilityConnection> &connection));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_PROVIDER_ACQUIRE_ERROR_HANDLER_H
