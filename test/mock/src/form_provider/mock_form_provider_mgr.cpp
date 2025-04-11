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

#include "form_provider/mock_form_provider_mgr.h"

namespace {
    bool g_mockRefreshCheck = true;
}

void MockRefreshCheck(bool mockRet)
{
    g_mockRefreshCheck = mockRet;
}

namespace OHOS {
namespace AppExecFwk {

FormProviderMgr::FormProviderMgr()
{}

FormProviderMgr::~FormProviderMgr()
{}

ErrCode FormProviderMgr::RefreshCheck(FormRecord &record, const int64_t formId, const Want &want)
{
    if (g_mockRefreshCheck) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}
} // namespace AppExecFwk
} // namespace OHOS
