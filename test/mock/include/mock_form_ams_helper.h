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
 */

#ifndef OHOS_FORM_FWK_MOCK_FORM_AMS_HELPER_H
#define OHOS_FORM_FWK_MOCK_FORM_AMS_HELPER_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "want.h"
#include "ability_connect_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class AbstractMockFormAmsHelper {
public:
    virtual ~AbstractMockFormAmsHelper() = default;
    virtual ErrCode StartAbility(const Want &want, int32_t userId) = 0;
    virtual ErrCode ConnectServiceAbilityWithUserId(
        const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId) = 0;
};

class MockFormAmsHelper : public AbstractMockFormAmsHelper {
public:
    static std::shared_ptr<MockFormAmsHelper> obj;
    MockFormAmsHelper() = default;
    ~MockFormAmsHelper() override = default;
    MOCK_METHOD2(StartAbility, ErrCode(const Want &want, int32_t userId));
    MOCK_METHOD3(ConnectServiceAbilityWithUserId, ErrCode(const Want &want,
        const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_AMS_HELPER_H
