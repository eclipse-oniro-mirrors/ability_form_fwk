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

#include "form_render/form_render_mgr.h"

namespace {
    bool g_mockGetIsSecondMounted = true;
}

void MockGetIsSecondMounted(bool mockRet)
{
    g_mockGetIsSecondMounted = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
bool FormRenderMgr::GetIsSecondMounted() const
{
    return g_mockGetIsSecondMounted;
}
}  // namespace AppExecFwk
}  // namespace OHOS
