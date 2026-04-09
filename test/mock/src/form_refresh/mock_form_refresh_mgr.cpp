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

#include "form_refresh/mock_form_refresh_mgr.h"
#include <gtest/gtest.h>
#include "form_refresh/form_refresh_mgr.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    std::vector<int32_t> g_mockBatchRequestRefreshErrorCodes;
}

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormRefreshMgr> MockFormRefreshMgr::obj = nullptr;

void MockFormRefreshMgr::MockBatchRequestRefresh(const std::vector<int32_t> &errorCodes)
{
    g_mockBatchRequestRefreshErrorCodes = errorCodes;
}

int FormRefreshMgr::RequestRefresh(RefreshData &data, const int32_t refreshType)
{
    GTEST_LOG_(INFO) << "FormRefreshMgr::RequestRefresh called";
    if (MockFormRefreshMgr::obj) {
        return MockFormRefreshMgr::obj->RequestRefresh(data, refreshType);
    }
    return ERR_OK;
}

int32_t FormRefreshMgr::BatchRequestRefresh(const int32_t refreshType,
    const StaggerStrategyType strategyType, std::vector<RefreshData> &batch)
{
    GTEST_LOG_(INFO) << "FormRefreshMgr::BatchRequestRefresh called, batch size: " << batch.size();
    for (size_t i = 0; i < batch.size() && i < g_mockBatchRequestRefreshErrorCodes.size(); ++i) {
        batch[i].errorCode = g_mockBatchRequestRefreshErrorCodes[i];
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
