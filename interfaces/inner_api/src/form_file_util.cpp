/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "form_file_util.h"

#include <dirent.h>
#include "directory_ex.h"

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

void FormFileUtil::GetDirFiles(const std::string &path, std::vector<std::string> &files)
{
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        HILOG_ERROR("failed to open file: %{public}s, error: %{public}d", path.c_str(), errno);
        return;
    }
 
    std::string pathStringWithDelimiter;
    while (true) {
        struct dirent *ptr = readdir(dir);
        if (ptr == nullptr) {
            HILOG_INFO("The file has been traversed");
            break;
        }
 
        // current dir OR parent dir
        if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
            continue;
        } else if (ptr->d_type == DT_DIR) {
            pathStringWithDelimiter = IncludeTrailingPathDelimiter(path) + std::string(ptr->d_name);
            GetDirFiles(pathStringWithDelimiter, files);
        } else {
            files.push_back(IncludeTrailingPathDelimiter(path) + std::string(ptr->d_name));
        }
    }
    closedir(dir);
}
 
void FormFileUtil::GetFilesSize(std::vector<std::string> &files, std::vector<std::uint64_t> &filesSize)
{
    struct stat statbuf = {0};
    uint64_t totalSize = 0;
    for (auto &file : files) {
        if (stat(file.c_str(), &statbuf) == 0) {
            filesSize.emplace_back(static_cast<uint64_t>(statbuf.st_size));
            totalSize += static_cast<uint64_t>(statbuf.st_size);
        }
    }
    filesSize.emplace_back(totalSize);
}
} // namespace AppExecFwk
} // namespace OHOS
