/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FMS_LOG_WRAPPER_H
#define OHOS_FORM_FWK_FMS_LOG_WRAPPER_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG
#include <cinttypes>
#include <functional>

#include <list>

#include "hilog/log.h"
#include "form_constants.h"

#ifdef HILOG_FATAL
#undef HILOG_FATAL
#endif

#ifdef HILOG_ERROR
#undef HILOG_ERROR
#endif

#ifdef HILOG_WARN
#undef HILOG_WARN
#endif

#ifdef HILOG_INFO
#undef HILOG_INFO
#endif

#ifdef HILOG_BRIEF
#undef HILOG_BRIEF
#endif

#ifdef HILOG_DEBUG
#undef HILOG_DEBUG
#endif

#ifndef FMS_LOG_DOMAIN
#define FMS_LOG_DOMAIN 0xD001301
#endif

#ifndef FMS_LOG_TAG
#define FMS_LOG_TAG "FormManagerService"
#endif

#ifndef FMS_FUNC_FMT
#define FMS_FUNC_FMT "[%{public}s(%{public}s:%{public}d)]"
#endif

#ifndef FMS_FUNC_FMT_BRIEF
#define FMS_FUNC_FMT_BRIEF "[%{public}s:%{public}d]"
#endif

#ifndef FMS_FILE_NAME
struct Cache {
    std::unordered_map<std::string, std::string> data;
    std::list<std::string> lru;
};

static inline Cache& GetCache()
{
    static Cache cache;
    return cache;
}

static inline void UpdateCache(const std::string& filename, const std::string& result)
{
    auto& cache = GetCache();
    if (cache.data.size() >= OHOS::AppExecFwk::Constants::MAX_FILE_LOG_CACHE_SIZE) {
        cache.data.erase(cache.lru.back());
        cache.lru.pop_back();
    }
    cache.data[filename] = result.empty() ? "" : result;
    cache.lru.push_front(filename);
}

static inline void ProcessUnderscoreChars(const char* base, std::string& result)
{
    for (const char* p = base; *p; p++) {
        if (*p == '_' && p[1] && p[1] != '_') {
            result += std::toupper(p[1]);
        }
    }
}

static inline std::string CalculateInitials(const char* filename)
{
    const char* base = __builtin_strrchr(filename, '/') ? __builtin_strrchr(filename, '/') + 1 : filename;
    std::string result;
    if (base[0] && base[0] != '_') {
        result += std::toupper(base[0]);
    }
    ProcessUnderscoreChars(base, result);
    return result;
}

static inline const char* GetCachedResult(const char* filename)
{
    auto& cache = GetCache();
    auto it = cache.data.find(filename);
    if (it != cache.data.end()) {
        cache.lru.remove(filename);
        cache.lru.push_front(filename);
        return it->second.c_str();
    }
    
    std::string result = CalculateInitials(filename);
    UpdateCache(filename, result);
    return cache.data[filename].c_str();
}

static inline const char* GetUnderscoreInitials(const char* filename)
{
    return GetCachedResult(filename);
}

#define FMS_FILE_NAME GetUnderscoreInitials(__FILE__)
#endif

#ifndef FMS_FUNC_INFO
#define FMS_FUNC_INFO FMS_FILE_NAME, __FUNCTION__, __LINE__
#endif

#ifndef FMS_FUNC_INFO_BRIEF
#define FMS_FUNC_INFO_BRIEF FMS_FILE_NAME, __LINE__
#endif

#define HILOG_ERROR(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_ERROR, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT fmt, FMS_FUNC_INFO, ##__VA_ARGS__);                   \
} while (0)

#define HILOG_WARN(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_WARN, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT fmt, FMS_FUNC_INFO, ##__VA_ARGS__);                  \
} while (0)

#define HILOG_INFO(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT fmt, FMS_FUNC_INFO, ##__VA_ARGS__);                  \
} while (0)

#define HILOG_BRIEF(fmt, ...) do { \
(void)HILOG_IMPL(LOG_CORE, LOG_INFO, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
FMS_FUNC_FMT_BRIEF fmt, FMS_FUNC_INFO_BRIEF, ##__VA_ARGS__);                  \
} while (0)

#define HILOG_DEBUG(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_DEBUG, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT fmt, FMS_FUNC_INFO, ##__VA_ARGS__);                   \
} while (0)

#define HILOG_FATAL(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_FATAL, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT fmt, FMS_FUNC_INFO, ##__VA_ARGS__);                   \
} while (0)

#else

#define HILOG_FATAL(...)
#define HILOG_ERROR(...)
#define HILOG_WARN(...)
#define HILOG_INFO(...)
#define HILOG_DEBUG(...)

#endif  // CONFIG_HILOG
#endif  // OHOS_FORM_FWK_FMS_LOG_WRAPPER_H
