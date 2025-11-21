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

#include "ets_live_form_extension_instance.h"

#include <cstddef>
#include <dlfcn.h>

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *ETS_ANI_LIBNAME = "liblive_form_extension_ani.z.so";
const char *ETS_ANI_CREATE_FUNC = "OHOS_ETS_Live_Form_Extension_Create";
using CreateCreateETSLiveFormExtensionFunc = LiveFormExtension*(*)(const std::unique_ptr<Runtime>&);
CreateCreateETSLiveFormExtensionFunc g_etsCreateFunc = nullptr;
}

LiveFormExtension *CreateETSLiveFormExtension(const std::unique_ptr<Runtime> &runtime)
{
    if (g_etsCreateFunc != nullptr) {
        return g_etsCreateFunc(runtime);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        HILOG_ERROR("dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return nullptr;
    }
    auto symbol = dlsym(handle, ETS_ANI_CREATE_FUNC);
    if (symbol == nullptr) {
        HILOG_ERROR("dlsym failed %{public}s, %{public}s", ETS_ANI_CREATE_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }
    g_etsCreateFunc = reinterpret_cast<CreateCreateETSLiveFormExtensionFunc>(symbol);
    return g_etsCreateFunc(runtime);
}
} // namespace AbilityRuntime
} // namespace OHOS