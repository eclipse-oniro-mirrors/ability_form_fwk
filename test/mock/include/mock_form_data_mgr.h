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

#ifndef OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormDataMgr {
public:
    virtual ~AbstractMockFormDataMgr() = default;
    virtual bool GetFormRecord(const int64_t formId, FormRecord &formRecord) = 0;
    virtual void CheckForms(const std::vector<int64_t> &formIds) = 0;
};

class MockFormDataMgr : public AbstractMockFormDataMgr {
public:
    static std::shared_ptr<MockFormDataMgr> obj;
    MockFormDataMgr() = default;
    ~MockFormDataMgr() override = default;
    MOCK_METHOD2(GetFormRecord, bool(const int64_t formId, FormRecord &formRecord));
    MOCK_METHOD1(CheckForms, void(const std::vector<int64_t> &formIds));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_DATA_MGR_H
