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
#ifdef RES_SCHEDULE_ENABLE

#include "form_systemload_listener.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormSystemloadListener::FormSystemloadListener(OnSystemloadLevelCb callback)
    : systemloadLevelCb_(callback)
{
}

void FormSystemloadListener::OnSystemloadLevel(int32_t level)
{
    HILOG_INFO("systemloadlevel is changed to %{public}d", level);
    if (systemloadLevelCb_ == nullptr) {
        return;
    }
    systemloadLevelCb_(level);
}
} // AppExecFwk
} // OHOS
#endif // RES_SCHEDULE_ENABLE