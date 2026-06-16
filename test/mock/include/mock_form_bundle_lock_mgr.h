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

#ifndef OHOS_FORM_FWK_MOCK_FORM_BUNDLE_LOCK_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_BUNDLE_LOCK_MGR_H

#include <cstdint>
#include <memory>
#include <string>
#include "gmock/gmock.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormBundleLockMgr {
public:
    virtual ~AbstractMockFormBundleLockMgr() = default;
    virtual bool IsBundleProtect(const std::string &bundleName, const int32_t userId, int64_t formId) = 0;
    virtual bool IsBundleLock(const std::string &bundleName, const int32_t userId, int64_t formId) = 0;
    virtual void SetBundleLockStatus(const std::string &bundleName, bool isLock) = 0;
    virtual void SetBundleProtectStatus(const std::string &bundleName, bool isProtect) = 0;
    virtual bool IsLockServiceInitialized() const = 0;
};

class MockFormBundleLockMgr : public AbstractMockFormBundleLockMgr {
public:
    static std::shared_ptr<MockFormBundleLockMgr> obj;
    MockFormBundleLockMgr() = default;
    ~MockFormBundleLockMgr() override = default;
    MOCK_METHOD3(IsBundleProtect, bool(const std::string &bundleName, const int32_t userId, int64_t formId));
    MOCK_METHOD3(IsBundleLock, bool(const std::string &bundleName, const int32_t userId, int64_t formId));
    MOCK_METHOD2(SetBundleLockStatus, void(const std::string &bundleName, bool isLock));
    MOCK_METHOD2(SetBundleProtectStatus, void(const std::string &bundleName, bool isProtect));
    MOCK_CONST_METHOD0(IsLockServiceInitialized, bool());
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_BUNDLE_LOCK_MGR_H
