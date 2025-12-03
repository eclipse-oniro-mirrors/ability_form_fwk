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

#ifndef OHOS_FORM_FWK_MOCK_PARAM_CONTROL_H
#define OHOS_FORM_FWK_MOCK_PARAM_CONTROL_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockParamControl {
public:
    virtual ~AbstractMockParamControl() = default;
    virtual bool IsFormDisable(const FormRecord &formRecord) = 0;
    virtual bool IsFormRemove(const FormRecord &formRecord) = 0;
};

class MockParamControl : public AbstractMockParamControl {
public:
    static std::shared_ptr<MockParamControl> obj;
    MockParamControl() = default;
    ~MockParamControl() override = default;
    MOCK_METHOD1(IsFormDisable, bool(const FormRecord &formRecord));
    MOCK_METHOD1(IsFormRemove, bool(const FormRecord &formRecord));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_PARAM_CONTROL_H
