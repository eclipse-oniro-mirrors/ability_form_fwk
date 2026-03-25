/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this is file except in compliance with the License.
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

#ifndef OHOS_FORM_FWK_MOCK_FORM_MGR_ADAPTER_H
#define OHOS_FORM_FWK_MOCK_FORM_MGR_ADAPTER_H

#include "gmock/gmock.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormMgrAdapter {
public:
    virtual ~AbstractMockFormMgrAdapter() = default;
    virtual bool IsDeleteCacheInUpgradeScene(const FormRecord &record) = 0;
};

class MockFormMgrAdapter : public AbstractMockFormMgrAdapter {
public:
    static std::shared_ptr<MockFormMgrAdapter> obj;
    MockFormMgrAdapter() = default;
    ~MockFormMgrAdapter() override = default;
    MOCK_METHOD1(IsDeleteCacheInUpgradeScene, bool(const FormRecord &record));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_MGR_ADAPTER_H