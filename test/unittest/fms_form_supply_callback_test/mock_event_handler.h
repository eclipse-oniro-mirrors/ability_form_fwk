/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_MOCK_FORM_EVENT_HANDLER_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_MOCK_FORM_EVENT_HANDLER_H

#include "form_event_handler.h"

namespace OHOS {
namespace AppExecFwk {
class MockFormEventTimeoutObserver : public FormEventTimeoutObserver {
public:
    MockFormEventTimeoutObserver() = default;
    virtual ~MockFormEventTimeoutObserver() = default;

    void OnEventTimeoutResponse(int64_t msg, int64_t eventId) override;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_MOCK_FORM_EVENT_HANDLER_H

