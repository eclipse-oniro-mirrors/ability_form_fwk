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

#include "batch_refresh/mock_default_stagger_strategy.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockDefaultStaggerStrategy> MockDefaultStaggerStrategy::obj = nullptr;

int32_t DefaultStaggerStrategy::ExecuteRefresh(std::vector<RefreshData> &batch, int32_t refreshType)
{
    GTEST_LOG_(INFO) << "DefaultStaggerStrategy::ExecuteRefresh called";
    if (MockDefaultStaggerStrategy::obj) {
        return MockDefaultStaggerStrategy::obj->ExecuteRefresh(batch, refreshType);
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
