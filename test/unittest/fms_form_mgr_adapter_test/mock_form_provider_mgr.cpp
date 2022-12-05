/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_provider_mgr.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockNotifyProviderFormDeleteRet = true;
}

void MockNotifyProviderFormDelete(bool mockRet)
{
    g_mockNotifyProviderFormDeleteRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormProviderMgr::FormProviderMgr() {}
FormProviderMgr::~FormProviderMgr() {}

ErrCode FormProviderMgr::NotifyProviderFormDelete(const int64_t formId, const FormRecord &formRecord)
{
    if (true == g_mockNotifyProviderFormDeleteRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}
}  // namespace AppExecFwk
}  // namespace OHOS
