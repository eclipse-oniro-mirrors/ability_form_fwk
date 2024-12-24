/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef APP_LOCK_UTILS_SPECIAL_MEMBER_FUNCTION_UTILS_H
#define APP_LOCK_UTILS_SPECIAL_MEMBER_FUNCTION_UTILS_H

namespace OHOS {
namespace AppSecurityPrivacy {
namespace AppLock {
namespace Utils {
/**
 * @brief Declare default the copy and move constructors and assignment operators.
 */
#define DEFAULT_COPY_AND_MOVE(className) \
    DEFAULT_COPY(className);             \
    DEFAULT_MOVE(className)

/**
 * @brief Declare default the copy constructors and assignment operators.
 */
#define DEFAULT_COPY(className)             \
    className(const className &) = default; \
    className &operator = (const className &) = default

/**
 * @brief Declare default the move constructors and assignment operators.
 */
#define DEFAULT_MOVE(className)        \
    className(className &&) = default; \
    className &operator = (className &&) = default

/**
 * @brief Delete the copy and move constructors and assignment operators.
 */
#define DELETE_COPY_AND_MOVE(className) \
    DELETE_COPY(className);             \
    DELETE_MOVE(className)

/**
 * @brief Delete the copy constructors and assignment operators.
 */
#define DELETE_COPY(className)             \
    className(const className &) = delete; \
    className &operator = (const className &) = delete

/**
 * @brief Delete the move constructors and assignment operators.
 */
#define DELETE_MOVE(className)        \
    className(className &&) = delete; \
    className &operator = (className &&) = delete
} // namespace Utils
} // namespace AppLock
} // namespace AppSecurityPrivacy
} // namespace OHOS

#endif // APP_LOCK_UTILS_SPECIAL_MEMBER_FUNCTION_UTILS_H
