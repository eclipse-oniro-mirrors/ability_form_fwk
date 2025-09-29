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
#include <unordered_map>

#include "ani.h"
#include "ani_getfromcache.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
AniGetFromCache::AniGetFromCache()
{
    HILOG_INFO("Create");
}

AniGetFromCache::~AniGetFromCache()
{
    HILOG_INFO("Destroy");
}

ani_status AniGetFromCache::AniFormGetCls(ani_env *env, const char *signature, ani_class &cls) {
    ani_status status = ANI_OK;

    std::lock_guard<std::mutex> lock(aniClsCacheMutex_);
    auto iter = aniClsCache_.find(signature);
    if (iter != aniClsCache_.end()) {
        cls = reinterpret_cast<ani_class>(iter->second);
        return status;
    }
    status = env->FindClass(signature, &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("AniFormGetCls FindClass failed status %{public}d ", static_cast<int>(status));
        return ANI_ERROR;
    }
    ani_ref ref = nullptr;
    status = env->GlobalReference_Create(cls, &ref);
    if (status != ANI_OK) {
        HILOG_ERROR("AniFormGetCls GlobalReference_Create failed status %{public}d ", static_cast<int>(status));
        return status;
    }
    aniClsCache_.emplace(signature, ref);
    HILOG_INFO("AniFormGetCls end");
    return status;
}

ani_status AniGetFromCache::AniFormGetMtd(
    ani_env *env, ani_class &cls, const char *name, const char *signature, ani_method &mtd) {
    ani_status status = ANI_OK;

    std::lock_guard<std::mutex> lock(aniMtdCacheMutex_);
    auto iter = aniMtdCache_.find(cls);
    if (iter != aniMtdCache_.end()) {
        mtd = reinterpret_cast<ani_method>(iter->second);
        return status;
    }
    status = env->Class_FindMethod(cls, name, signature, &mtd);
    if (status != ANI_OK) {
        HILOG_ERROR("AniFormGetMtd Class_FindMethod failed status %{public}d ", static_cast<int>(status));
        return ANI_ERROR;
    }
    aniMtdCache_.emplace(cls, mtd);
    HILOG_INFO("AniFormGetMtd end");
    return status;
}
} // namespace AppExecFwk
} // namespace OHOS