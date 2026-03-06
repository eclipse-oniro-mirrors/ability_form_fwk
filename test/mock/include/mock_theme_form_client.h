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

#ifndef OHOS_FORM_FWK_MOCK_THEME_FORM_CLIENT_H
#define OHOS_FORM_FWK_MOCK_THEME_FORM_CLIENT_H

#include <cstdint>
#include <memory>
#include <vector>
#include "gmock/gmock.h"
#include "feature/theme_form/theme_form_client.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockThemeFormClient {
public:
    virtual ~AbstractMockThemeFormClient() = default;
    virtual int32_t AddForm(const FormNotifyInfo& info) = 0;
    virtual int32_t DeleteForms(const std::vector<int64_t> &formIds) = 0;
};

class MockThemeFormClient : public AbstractMockThemeFormClient {
public:
    static std::shared_ptr<MockThemeFormClient> obj;
    MockThemeFormClient() = default;
    ~MockThemeFormClient() override = default;
    MOCK_METHOD1(AddForm, int32_t(const FormNotifyInfo& info));
    MOCK_METHOD1(DeleteForms, int32_t(const std::vector<int64_t> &formIds));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_THEME_FORM_CLIENT_H
