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

#include "feature/param_update/sign_tools.h"

#include <unistd.h>
#include <fstream>       // for ifstream
#include <openssl/bio.h> // bio
#include <openssl/evp.h> // evp
#include <openssl/pem.h> // PEM_read_bio_RSA_PUBKEY
#include <openssl/rsa.h> // rsa
#include <sstream>       // stringstream
#include <cstdlib>
#include <climits>

#include "common/util/file_utils.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
bool SignTools::VerifyFileSign(const std::string &pubKeyPath, const std::string &singPath,
    const std::string &digestPath)
{
    if (!(FileUtils::IsFileExists(pubKeyPath) && FileUtils::IsFileExists(singPath) &&
        FileUtils::IsFileExists(digestPath))) {
        HILOG_ERROR("file not exist");
        return false;
    }

    const std::string signStr = GetfileStream(singPath);
    const std::string digeststr = GetfileStream(digestPath);

    BIO *bio = BIO_new_file(pubKeyPath.c_str(), "r");

    RSA *pubKey = RSA_new();

    if (PEM_read_bio_RSA_PUBKEY(bio, &pubKey, NULL, NULL) == NULL) {
        HILOG_ERROR("get pubKey is failed");
        BIO_free(bio);
        RSA_free(pubKey);
        return false;
    }

    bool verify = false;
    if (!(pubKey == NULL || signStr.empty() || digeststr.empty())) {
        verify = VerifyRsa(pubKey, digeststr, signStr);
    } else {
        HILOG_ERROR("param is null");
    }
    BIO_free(bio);
    RSA_free(pubKey);
    return verify;
}

bool SignTools::VerifyRsa(RSA *pubKey, const std::string &digest, const std::string &sign)
{
    EVP_PKEY *evpKey = NULL;
    EVP_MD_CTX *ctx = NULL;
    evpKey = EVP_PKEY_new();
    if (evpKey == nullptr) {
        HILOG_ERROR("evpKey is nullptr");
        return false;
    }
    if (EVP_PKEY_set1_RSA(evpKey, pubKey) != 1) {
        HILOG_ERROR("EVP_PKEY_set1_RSA fail");
        EVP_PKEY_free(evpKey);
        return false;
    }
    ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    if (ctx == nullptr) {
        HILOG_ERROR("ctx is nullptr");
        EVP_PKEY_free(evpKey);
        return false;
    }
    if (EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        HILOG_ERROR("EVP_VerifyInit_ex fail");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyUpdate(ctx, digest.c_str(), digest.size()) != 1) {
        HILOG_ERROR("EVP_VerifyUpdate fail");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }
    if (EVP_VerifyFinal(ctx, (unsigned char *)sign.c_str(), sign.size(), evpKey) != 1) {
        HILOG_ERROR("EVP_VerifyFinal fail)");
        EVP_PKEY_free(evpKey);
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_free(evpKey);
    EVP_MD_CTX_free(ctx);
    return true;
}

std::string SignTools::GetfileStream(const std::string &filepath)
{
    std::string fileString;
    char canonicalPath[PATH_MAX + 1] = { '\0' };
    if (realpath(filepath.c_str(), canonicalPath) == nullptr) {
        HILOG_ERROR("canonicalPath is null");
        return fileString;
    }
    std::ifstream file(canonicalPath, std::ios::in | std::ios::binary);
    if (!file.good()) {
        HILOG_ERROR("Failed to open the file!");
        return fileString;
    }
    std::stringstream infile;
    infile << file.rdbuf();
    fileString = infile.str();
    file.close();
    return fileString;
}


std::tuple<int, std::string> SignTools::CalcFileSha256Digest(const std::string &fpath)
{
    auto res = std::make_unique<unsigned char[]>(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    auto sha256Update = [ctx = &ctx](char *buf, size_t len) { SHA256_Update(ctx, buf, len); };
    int err = ForEachFileSegment(fpath, sha256Update);
    SHA256_Final(res.get(), &ctx);
    if (err) {
        return { err, "" };
    }
    std::string dist;
    CalcBase64(res.get(), SHA256_DIGEST_LENGTH, dist);
    return { err, dist };
};

int SignTools::ForEachFileSegment(const std::string &fpath, std::function<void(char *, size_t)> executor)
{
    char canonicalPath[PATH_MAX + 1] = { '\0' };
    if (realpath(fpath.c_str(), canonicalPath) == nullptr) {
        HILOG_ERROR("canonicalPath is null");
        return errno;
    }
    std::unique_ptr<FILE, decltype(&fclose)> filp = { fopen(canonicalPath, "r"), fclose };
    if (!filp) {
        return errno;
    }
    const size_t pageSize { getpagesize() };
    auto buf = std::make_unique<char[]>(pageSize);
    size_t actLen;
    do {
        actLen = fread(buf.get(), 1, pageSize, filp.get());
        if (actLen > 0) {
            executor(buf.get(), actLen);
        }
    } while (actLen == pageSize);

    return ferror(filp.get()) ? errno : 0;
}

void SignTools::CalcBase64(uint8_t *input, uint32_t inputLen, std::string &encodedStr)
{
    size_t expectedLength = 4 * ((inputLen + 2) / 3);
    encodedStr.resize(expectedLength);
    int actualLength = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(&encodedStr[0]), input, inputLen);
    encodedStr.resize(actualLength);
    HILOG_INFO("expectedLength = %{public}zu, actualLength = %{public}d", expectedLength, actualLength);
}
}  // namespace AppExecFwk
}  // namespace OHOS