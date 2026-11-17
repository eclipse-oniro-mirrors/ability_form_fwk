#ifndef INNER_MOCK_FORM_FILE_UTIL_H
#define INNER_MOCK_FORM_FILE_UTIL_H

#include <cstdint>
#include <string>
#include <vector>

void MockGetDirFilesResult(const std::vector<std::string> &files);
void MockGetFilesSizeResult(uint64_t size);
void ResetFormFileUtilMock();

#endif // INNER_MOCK_FORM_FILE_UTIL_H
