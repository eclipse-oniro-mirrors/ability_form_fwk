/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "json_util_form.h"

#include "nlohmann/json.hpp"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief Update bracket nesting depth and check for negative depth.
 * @param c Bracket character to process ('{', '[', '}', or ']').
 * @param currentDepth Current nesting depth (modified in-place).
 * @return true if depth remains valid; false if currentDepth goes negative.
 */
static bool UpdateBracketDepth(char c, int32_t &currentDepth)
{
    if (c == '{' || c == '[') {
        currentDepth++;
    } else if (c == '}' || c == ']') {
        currentDepth--;
        if (currentDepth < 0) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Check whether JSON bracket nesting depth is within safe limits.
 * @param jsonStr JSON string to scan.
 * @return true if brackets balanced, depth within MAX_JSON_PARSE_DEPTH,
 *         and no unclosed strings; false otherwise.
 */
static bool IsJsonDepthSafe(const std::string &jsonStr)
{
    int32_t currentDepth = 0;
    bool inString = false;
    bool escapeNext = false;
    for (char c : jsonStr) {
        if (escapeNext) {
            escapeNext = false;
            continue;
        }
        if (c == '\\' && inString) {
            escapeNext = true;
            continue;
        }
        if (c == '"') {
            inString = !inString;
            continue;
        }
        if (inString) {
            continue;
        }
        if (!UpdateBracketDepth(c, currentDepth)) {
            return false;
        }
        if (currentDepth > MAX_JSON_PARSE_DEPTH) {
            return false;
        }
    }
    return (currentDepth == 0) && !inString;
}

nlohmann::json SafeJsonParse(const std::string &jsonStr, bool allowExceptions)
{
    if (jsonStr.empty()) {
        return nlohmann::json(nlohmann::json::value_t::discarded);
    }
    if (!IsJsonDepthSafe(jsonStr)) {
        HILOG_ERROR("JSON depth exceeds limit or brackets unbalanced");
        return nlohmann::json(nlohmann::json::value_t::discarded);
    }
    return nlohmann::json::parse(jsonStr, nullptr, allowExceptions);
}
}  // namespace AppExecFwk
}  // namespace OHOS
