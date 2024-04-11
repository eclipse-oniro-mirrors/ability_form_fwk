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

#include "form_memmgr_client.h"

#include <functional>
#include <dlfcn.h>
#include <unistd.h>
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t FORM_RENDER_SERVICE_SAID = -1;

FormMemmgrClient::FormMemmgrClient()
{}

FormMemmgrClient::~FormMemmgrClient()
{}

void FormMemmgrClient::SetCritical(bool critical)
{
    int32_t pid = getpid();
    HILOG_INFO("%{public}s, pid:%{public}" PRId32 ", critical:%{public}d.", __func__, pid, critical);

    void *libMemmgrClientHandle = dlopen("libmemmgrclient.z.so", RTLD_NOW);
    if (!libMemmgrClientHandle) {
        HILOG_ERROR("%{public}s, dlopen libmemmgrclient fail.", __func__);
        return;
    }

    void *setCritical = (dlsym(libMemmgrClientHandle, "set_critical"));
    if (!setCritical) {
        HILOG_ERROR("%{public}s, dlsym set_critical fail.", __func__);
        dlclose(libMemmgrClientHandle);
        return;
    }

    auto setCriticalFunc = reinterpret_cast<int32_t(*)(int32_t, bool, int32_t)>(setCritical);
    if (setCriticalFunc(pid, critical, FORM_RENDER_SERVICE_SAID) != 0) {
        HILOG_ERROR("%{public}s, setCriticalFunc fail.", __func__);
    }
    dlclose(libMemmgrClientHandle);
}
} // namespace AppExecFwk
} // namespace OHOS
