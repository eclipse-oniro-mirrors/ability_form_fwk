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

#include "form_refresh/strategy/refresh_check_mgr.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    OHOS::ErrCode g_mockCheckValid = OHOS::ERR_OK;
}

namespace OHOS {
void MockIsBaseValidPass(OHOS::ErrCode mockRet)
{
    g_mockCheckValid = mockRet;
}
}

namespace OHOS {
namespace AppExecFwk {
RefreshCheckMgr::RefreshCheckMgr()
{}

RefreshCheckMgr::~RefreshCheckMgr()
{}

ErrCode RefreshCheckMgr::IsBaseValidPass(const std::vector<int32_t> &types, const CheckValidFactor &factor)
{
    return g_mockCheckValid;
}
} // namespace AppExecFwk
} // namespace OHOS
