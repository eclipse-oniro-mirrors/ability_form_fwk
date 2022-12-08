/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_info_mgr.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockGetFormsInfoByBundleRet = true;
}

void MockGetFormsInfoByBundle(bool mockRet)
{
    g_mockGetFormsInfoByBundleRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
ErrCode FormInfoMgr::GetFormsInfoByBundle(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    if (true == g_mockGetFormsInfoByBundleRet) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
