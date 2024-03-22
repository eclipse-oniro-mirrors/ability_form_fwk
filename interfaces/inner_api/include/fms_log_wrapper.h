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

#include "hilog/log.h"

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

#ifndef FMS_FILE_NAME
#define FMS_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef FMS_FUNC_INFO
#define FMS_FUNC_INFO FMS_FILE_NAME, __FUNCTION__, __LINE__
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
