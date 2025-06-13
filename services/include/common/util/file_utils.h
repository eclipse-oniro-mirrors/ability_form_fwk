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

#ifndef OHOS_FORM_FWK_FILE_UTILS_H
#define OHOS_FORM_FWK_FILE_UTILS_H

#include <fstream>
#include <iostream>
#include <string>
#include <cstdlib>
#include <climits>
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
class FileUtils {
public:
    static bool IsFileExists(const std::string &fileName)
    {
        char canonicalPath[PATH_MAX] = { '\0' };
        if (realpath(fileName.c_str(), canonicalPath) == nullptr) {
            HILOG_ERROR("canonicalPath is null");
            return false;
        }
        canonicalPath[PATH_MAX - 1] = '\0';
        std::ifstream file(canonicalPath);
        if (!file.good()) {
            HILOG_WARN("file not exists: %{public}s", fileName.c_str());
            return false;
        }
        return true;
    };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FILE_UTILS_H