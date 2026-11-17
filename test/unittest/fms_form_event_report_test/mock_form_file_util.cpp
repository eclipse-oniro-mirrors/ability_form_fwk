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

#include <gtest/gtest.h>
#include "form_file_util.h"
#include "fms_log_wrapper.h"

namespace {
// Mock size in bytes returned for each file in GetFilesSize
constexpr uint64_t MOCK_SINGLE_FILE_SIZE = 100;
std::vector<std::string> g_mockFiles;
uint64_t g_mockFilesSize = 0;
}

void MockGetDirFilesResult(const std::vector<std::string> &files)
{
    g_mockFiles = files;
}

void MockGetFilesSizeResult(uint64_t size)
{
    g_mockFilesSize = size;
}

void ResetFormFileUtilMock()
{
    g_mockFiles.clear();
    g_mockFilesSize = 0;
}

namespace OHOS {
namespace AppExecFwk {
void FormFileUtil::GetDirFiles(const std::string &path, std::vector<std::string> &files)
{
    HILOG_DEBUG("GetDirFiles called, path=%{public}s", path.c_str());
    files = g_mockFiles;
}

uint64_t FormFileUtil::GetFilesSize(const std::vector<std::string> &files, std::vector<std::uint64_t> &filesSize)
{
    HILOG_DEBUG("GetFilesSize called, files.size=%{public}zu", files.size());
    filesSize.clear();
    for (size_t i = 0; i < files.size(); i++) {
        filesSize.push_back(MOCK_SINGLE_FILE_SIZE);
    }
    return g_mockFilesSize;
}

std::string FormFileUtil::GetMaskedPath(const std::string &path)
{
    return path;
}
} // namespace AppExecFwk
} // namespace OHOS
