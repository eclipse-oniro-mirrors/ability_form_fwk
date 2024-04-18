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

#include "form_memory_guard.h"

#include "fms_log_wrapper.h"
#include "malloc.h"

namespace OHOS {
namespace AppExecFwk {
FormMemoryGuard::FormMemoryGuard()
{
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    int32_t setCacheRet = mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_DISABLE);
    int32_t setFreeRet = mallopt(M_DELAYED_FREE, M_DELAYED_FREE_DISABLE);
    HILOG_DEBUG("disable tcache and delay free, result:%{public}d, %{public}d", setCacheRet, setFreeRet);
#endif
}

FormMemoryGuard::~FormMemoryGuard()
{
#ifdef CONFIG_USE_JEMALLOC_DFX_INTF
    int32_t ret = mallopt(M_FLUSH_THREAD_CACHE, 0);
    HILOG_DEBUG("flush cache, result: %{public}d", ret);
#endif
}
} // namespace AppExecFwk
} // namespace OHOS
