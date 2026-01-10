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
#include "parameters.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_RENDER_SERVICE_TYPE = 3;
constexpr int32_t FORM_RENDER_SERVICE_STATUS = 1;
constexpr int32_t FORM_RENDER_SERVICE_SAID = -1;
constexpr const char *LIB_MEMMGR_CLIENT_NAME = "libmemmgrclient.z.so";
constexpr const char *CRITICAL_NOTIFY_PARAM_NAME = "const.form.mem_reduce.critical_notify_enable";
}

FormMemmgrClient::FormMemmgrClient()
{
    criticalNotifyEnable_ = system::GetBoolParameter(CRITICAL_NOTIFY_PARAM_NAME, true);
    NotifyProcessStatus();
}

FormMemmgrClient::~FormMemmgrClient()
{}

void FormMemmgrClient::SetCritical(bool critical)
{
    int32_t pid = getprocpid();
    HILOG_INFO("pid:%{public}" PRId32 ", critical:%{public}d", pid, critical);

    if (!critical && !criticalNotifyEnable_) {
        HILOG_ERROR("setCritical fail, critical notify enable is false");
        return;
    }
    void *libMemmgrClientHandle = dlopen(LIB_MEMMGR_CLIENT_NAME, RTLD_NOW);
    if (!libMemmgrClientHandle) {
        HILOG_ERROR("dlopen libmemmgrclient fail");
        return;
    }

    void *setCritical = (dlsym(libMemmgrClientHandle, "set_critical"));
    if (!setCritical) {
        HILOG_ERROR("dlsym set_critical fail");
        dlclose(libMemmgrClientHandle);
        return;
    }

    auto setCriticalFunc = reinterpret_cast<int32_t(*)(int32_t, bool, int32_t)>(setCritical);
    if (setCriticalFunc(pid, critical, FORM_RENDER_SERVICE_SAID) != 0) {
        HILOG_ERROR("setCriticalFunc fail");
    } else {
        critical_.store(critical);
    }
    dlclose(libMemmgrClientHandle);
}

void FormMemmgrClient::NotifyProcessStatus()
{
    void *libMemMgrClientHandle = dlopen(LIB_MEMMGR_CLIENT_NAME, RTLD_NOW);
    if (!libMemMgrClientHandle) {
        HILOG_ERROR("dlopen libmemmgrclient library failed");
        return;
    }
    void *notifyProcessStatusFunc = dlsym(libMemMgrClientHandle, "notify_process_status");
    if (!notifyProcessStatusFunc) {
        HILOG_ERROR("dlsm notify_process_status failed");
        dlclose(libMemMgrClientHandle);
        return;
    }
    auto notifyProcessStatus = reinterpret_cast<int(*)(int, int, int, int)>(notifyProcessStatusFunc);
    HILOG_INFO("notify to memmgr when frs start");
    int pid = getprocpid();
    notifyProcessStatus(pid, FORM_RENDER_SERVICE_TYPE, FORM_RENDER_SERVICE_STATUS, FORM_RENDER_SERVICE_SAID);
    dlclose(libMemMgrClientHandle);
}
} // namespace AppExecFwk
} // namespace OHOS
