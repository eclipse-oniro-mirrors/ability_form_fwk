/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef MOCK_OHOS_FORM_FWK_MOCK_FORM_SUPPLY_CALLBACK_H
#define MOCK_OHOS_FORM_FWK_MOCK_FORM_SUPPLY_CALLBACK_H

#include "form_supply_stub.h"

namespace OHOS {
namespace AppExecFwk {
class MockFormSupplyCallback : public FormSupplyStub {
public:
    MockFormSupplyCallback() = default;
    virtual ~MockFormSupplyCallback() = default;
    static sptr<MockFormSupplyCallback> GetInstance();

    int OnAcquire(const FormProviderInfo& formInfo, const Want& want) override;
    int OnEventHandle(const Want& want) override;
    int OnAcquireStateResult(FormState state, const std::string& provider, const Want& wantArg,
        const Want& want) override;
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override;
    void OnShareAcquire(int64_t formId, const std::string& remoteDeviceId, const AAFwk::WantParams& wantParams,
        int64_t requestCode, const bool& result) override;
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override;
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override;

private:
    static std::mutex mutex;
    static sptr<MockFormSupplyCallback> instance;

    DISALLOW_COPY_AND_MOVE(MockFormSupplyCallback);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // MOCK_OHOS_FORM_FWK_MOCK_FORM_SUPPLY_CALLBACK_H
