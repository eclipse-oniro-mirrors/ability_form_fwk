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

#ifndef OHOS_FORM_FWK_MOCK_FORM_EXEMPT_LOCK_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_EXEMPT_LOCK_MGR_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormExemptLockMgr {
public:
    virtual ~AbstractMockFormExemptLockMgr() = default;
    virtual bool IsExemptLock(int64_t formId) = 0;
    virtual void SetExemptLockStatus(int64_t formId, bool isExempt) = 0;
};

class MockFormExemptLockMgr : public AbstractMockFormExemptLockMgr {
public:
    static std::shared_ptr<MockFormExemptLockMgr> obj;
    MockFormExemptLockMgr() = default;
    ~MockFormExemptLockMgr() override = default;
    MOCK_METHOD1(IsExemptLock, bool(int64_t formId));
    MOCK_METHOD2(SetExemptLockStatus, void(int64_t formId, bool isExempt));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_EXEMPT_LOCK_MGR_H
