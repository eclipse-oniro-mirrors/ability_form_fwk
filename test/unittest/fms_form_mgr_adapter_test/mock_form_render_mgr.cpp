/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_render_mgr.h"

namespace {
    bool g_mockGetIsVerified = true;
}

void MockGetIsVerified(bool mockRet)
{
    g_mockGetIsVerified = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
bool FormRenderMgr::GetIsVerified() const
{
    return g_mockGetIsVerified;
}
}  // namespace AppExecFwk
}  // namespace OHOS
