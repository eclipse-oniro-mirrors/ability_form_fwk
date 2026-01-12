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

#include "feature/param_update/param_reader.h"

#include <memory>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <climits>
#include "common/util/string_utils.h"
#include "feature/param_update/sign_tools.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *CERT_ENC_FILE = "CERT.ENC";
constexpr const char *CERT_SF_FILE = "CERT.SF";
constexpr const char *MANIFEST_MF_FILE = "MANIFEST.MF";
constexpr const char *FILE_SHA_KEY = "Name: ";
constexpr const char *PUBKEY_PATH = "/system/etc/update/hwkey_param_upgrade_v1.pem";
}

ParamReader::ParamReader()
{
    HILOG_INFO("init");
}
ParamReader::~ParamReader()
{
    HILOG_INFO("destroy");
}

std::string ParamReader::GetPathVersion(const std::string &path)
{
    HILOG_INFO("GetPathVersion:%{public}s", path.c_str());
    if (path.empty()) {
        HILOG_ERROR("path is empty, return default version");
        return Constants::FMC_DEFAULT_VERSION;
    }
    char canonicalPath[PATH_MAX] = { '\0' };
    if (realpath((path + Constants::VERSION_FILE_NAME).c_str(), canonicalPath) == nullptr) {
        HILOG_ERROR("canonicalPath is null, return default version");
        return Constants::FMC_DEFAULT_VERSION;
    }
    canonicalPath[PATH_MAX - 1] = '\0';
    std::ifstream file(canonicalPath);
    if (!file.good()) {
        HILOG_ERROR("VersionFilePath is not good");
        return Constants::FMC_DEFAULT_VERSION;
    }
    std::string line;
    std::getline(file, line);
    std::string versionStr = StringUtils::split(line, '=')[1];
    StringUtils::trim(versionStr);
    file.close();
    return versionStr;
}

bool ParamReader::VerifyCertSfFile()
{
    std::string certFile = Constants::FORM_MGR_CONFIG_DIR + CERT_ENC_FILE;
    std::string verifyFile = Constants::FORM_MGR_CONFIG_DIR + CERT_SF_FILE;
    if (!SignTools::VerifyFileSign(PUBKEY_PATH, certFile, verifyFile)) {
        HILOG_ERROR("verify file sign failed");
        return false;
    }
    std::string sha256Digest = GetManifestSha256Digest();
    HILOG_INFO("sha256Digest:%{public}s", sha256Digest.c_str());
    if (sha256Digest.empty()) {
        HILOG_ERROR("sha256Digest is empty");
        return false;
    }
    std::string calSha256Digest = CalcFileSha256Digest(MANIFEST_MF_FILE);
    HILOG_INFO("calSha256Digest:%{public}s", calSha256Digest.c_str());
    if (calSha256Digest.empty()) {
        HILOG_ERROR("calSha256Digest is empty");
        return false;
    }
    return sha256Digest == calSha256Digest;
}

bool ParamReader::VerifyParamFile(const std::string &fileName)
{
    HILOG_INFO("VerifyParamFile ,fileName:%{public}s", fileName.c_str());
    std::string sha256Digest = GetSha256Digest(fileName);
    HILOG_INFO("sha256Digest:%{public}s", sha256Digest.c_str());
    if (sha256Digest.empty()) {
        HILOG_ERROR("sha256Digest is empty");
        return false;
    }
    std::string calSha256Digest = CalcFileSha256Digest(fileName);
    HILOG_INFO("calSha256Digest:%{public}s", calSha256Digest.c_str());
    if (calSha256Digest.empty()) {
        HILOG_ERROR("calSha256Digest is empty");
        return false;
    }
    return sha256Digest == calSha256Digest;
}

std::string ParamReader::GetParamInfoStr(const std::string &filePathStr)
{
    std::string paramInfo;
    char canonicalPath[PATH_MAX] = { '\0' };
    if (realpath(filePathStr.c_str(), canonicalPath) == nullptr) {
        HILOG_ERROR("canonicalPath is null");
        return paramInfo;
    }
    canonicalPath[PATH_MAX - 1] = '\0';
    std::ifstream file(canonicalPath, std::ios::in | std::ios::binary);
    if (!file.good()) {
        HILOG_ERROR("Failed to open the file!");
        return paramInfo;
    }
    std::stringstream infile;
    infile << file.rdbuf();
    paramInfo = infile.str();
    file.close();
    return paramInfo;
}

std::string ParamReader::GetManifestSha256Digest()
{
    std::string verifyFile = Constants::FORM_MGR_CONFIG_DIR + CERT_SF_FILE;
    std::ifstream file(verifyFile);
    std::string sha256Digest;
    if (!file.good()) {
        HILOG_ERROR("Verify file is not good");
        return sha256Digest;
    }
    std::string line;
    std::getline(file, line);
    file.close();
    sha256Digest = StringUtils::split(line, ':')[1];
    StringUtils::trim(sha256Digest);
    return sha256Digest;
}

std::string ParamReader::GetSha256Digest(const std::string &fileName)
{
    std::string manifestFile = Constants::FORM_MGR_CONFIG_DIR + MANIFEST_MF_FILE;
    std::ifstream file(manifestFile);
    std::string sha256Digest;
    if (!file.good()) {
        HILOG_ERROR("manifestFile is not good");
        return sha256Digest;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::string nextline;
        if (line.find(FILE_SHA_KEY + fileName) != std::string::npos) {
            std::getline(file, nextline);
            sha256Digest = StringUtils::split(nextline, ':')[1];
            StringUtils::trim(sha256Digest);
            break;
        }
    }
    file.close();
    return sha256Digest;
}

std::string ParamReader::CalcFileSha256Digest(const std::string &fileName)
{
    std::string filePath = Constants::FORM_MGR_CONFIG_DIR + fileName;
    std::string calSha256Digest;
    std::tuple<int, std::string> ret = SignTools::CalcFileSha256Digest(filePath);
    if (std::get<0>(ret) != 0) {
        HILOG_ERROR("CalcFileSha256Digest failed,error : %{public}d ", std::get<0>(ret));
        return calSha256Digest;
    }
    calSha256Digest = std::get<1>(ret);
    return calSha256Digest;
}
}  // namespace AppExecFwk
}  // namespace OHOS