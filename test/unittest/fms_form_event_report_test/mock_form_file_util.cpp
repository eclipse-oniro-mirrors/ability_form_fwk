#include <gtest/gtest.h>
#include "form_file_util.h"
#include "fms_log_wrapper.h"

namespace {
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
        filesSize.push_back(100);
    }
    return g_mockFilesSize;
}

std::string FormFileUtil::GetMaskedPath(const std::string &path)
{
    return path;
}
} // namespace AppExecFwk
} // namespace OHOS
