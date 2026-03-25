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

#ifndef OHOS_FORM_FWK_MOCK_FORM_RENDER_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_RENDER_MGR_H

#include "gmock/gmock.h"
#include "form_provider_data.h"
#include "want_params.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormRenderMgr {
public:
    virtual ~AbstractMockFormRenderMgr() = default;
    virtual int32_t UpdateRenderingForm(int64_t formId, const FormProviderData &formProviderData,
        const AAFwk::WantParams &wantParams, bool mergeData) = 0;
};

class MockFormRenderMgr : public AbstractMockFormRenderMgr {
public:
    static std::shared_ptr<MockFormRenderMgr> obj;
    MockFormRenderMgr() = default;
    ~MockFormRenderMgr() override = default;
    MOCK_METHOD4(UpdateRenderingForm, int32_t(int64_t formId, const FormProviderData &formProviderData,
        const AAFwk::WantParams &wantParams, bool mergeData));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_RENDER_MGR_H