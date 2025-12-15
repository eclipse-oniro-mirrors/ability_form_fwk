/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_STRING_UTILS_H
#define OHOS_FORM_FWK_STRING_UTILS_H

#include <algorithm>
#include <functional>
#include <regex>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
class StringUtils {
public:
    // trim from start (in place)
    static inline void ltrim(std::string &inputStr)
    {
        inputStr.erase(inputStr.begin(),
            std::find_if(inputStr.begin(), inputStr.end(), [](unsigned char ch) { return !std::isspace(ch); }));
    }

    // trim from end (in place)
    static inline void rtrim(std::string &inputStr)
    {
        inputStr.erase(
            std::find_if(inputStr.rbegin(), inputStr.rend(), [](unsigned char ch) { return !std::isspace(ch); }).base(),
            inputStr.end());
    }

    // trim from both ends (in place)
    static inline void trim(std::string &inputStr)
    {
        ltrim(inputStr);
        rtrim(inputStr);
    }

    static inline std::vector<std::string> split(const std::string &str, char delim)
    {
        std::vector<std::string> tokens;
        size_t start;
        size_t end = 0;
        while ((start = str.find_first_not_of(delim, end)) != std::string::npos) {
            end = str.find(delim, start);
            tokens.push_back(str.substr(start, end - start));
        }
        return tokens;
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_STRING_UTILS_H