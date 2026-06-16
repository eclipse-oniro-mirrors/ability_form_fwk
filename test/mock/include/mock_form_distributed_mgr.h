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

#ifndef OHOS_FORM_FWK_MOCK_FORM_DISTRIBUTED_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_DISTRIBUTED_MGR_H

#include <cstdint>
#include <memory>
#include <string>
#include "gmock/gmock.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormDistributedMgr {
public:
    virtual ~AbstractMockFormDistributedMgr() = default;
    virtual bool IsBundleDistributed(const std::string &bundleName, int32_t userId) = 0;
    virtual std::string GetUiModuleName(const std::string &bundleName, int32_t userId) = 0;
};

class MockFormDistributedMgr : public AbstractMockFormDistributedMgr {
public:
    static std::shared_ptr<MockFormDistributedMgr> obj;
    MockFormDistributedMgr() = default;
    ~MockFormDistributedMgr() override = default;
    MOCK_METHOD2(IsBundleDistributed, bool(const std::string &bundleName, int32_t userId));
    MOCK_METHOD2(GetUiModuleName, std::string(const std::string &bundleName, int32_t userId));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_DISTRIBUTED_MGR_H
