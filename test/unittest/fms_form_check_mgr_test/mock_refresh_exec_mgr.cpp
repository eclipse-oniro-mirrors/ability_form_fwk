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

#include "form_refresh/strategy/refresh_exec_mgr.h"

#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    OHOS::ErrCode g_mockAskData = OHOS::ERR_OK;
    OHOS::ErrCode g_mockUpdateData = OHOS::ERR_OK;
}

void MockAskForProviderData(OHOS::ErrCode mockRet)
{
    g_mockAskData = mockRet;
}

void MockUpdateByProviderData(OHOS::ErrCode mockRet)
{
    g_mockUpdateData = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

ErrCode RefreshExecMgr::AskForProviderData(const int64_t formId, const FormRecord &record, const Want &want)
{
    return g_mockAskData;
}

ErrCode RefreshExecMgr::UpdateByProviderData(
    const int64_t formId, const FormProviderData &formProviderData, bool mergeData)
{
    return g_mockUpdateData;
}
} // namespace AppExecFwk
} // namespace OHOS
