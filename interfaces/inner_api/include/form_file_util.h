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
#ifndef OHOS_FORM_FWK_FORM_FILE_UTIL_H
#define OHOS_FORM_FWK_FORM_FILE_UTIL_H

#include <set>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class FormFileUtil {
public:
    static void GetDirFiles(const std::string &path, std::vector<std::string> &files);
    static void GetFilesSize(std::vector<std::string> &files, std::vector<std::uint64_t> &filesSize);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_FILE_UTIL_H