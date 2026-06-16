/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include <gtest/gtest.h>

#include "feature/form_share/form_share_mgr.h"
#include "form_mgr_errors.h"

namespace {
    int32_t shareForm = OHOS::ERR_OK;
    int32_t g_recvFormShareInfoFromRemote = OHOS::ERR_OK;
}

void MockShareForm(bool mockRet)
{
    shareForm = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
int32_t FormShareMgr::ShareForm(
    int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken, int64_t requestCode)
{
    GTEST_LOG_(INFO) << "ShareForm called " << shareForm;
    return shareForm;
}

int32_t FormShareMgr::RecvFormShareInfoFromRemote(const FormShareInfo &info, const int32_t userId)
{
    return g_recvFormShareInfoFromRemote;
}
}  // namespace AppExecFwk
}  // namespace OHOS