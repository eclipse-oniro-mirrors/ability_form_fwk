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

#ifndef OHOS_FORM_FWK_SIGN_TOOLS_H
#define OHOS_FORM_FWK_SIGN_TOOLS_H

#include <string>
#include <openssl/rsa.h>

namespace OHOS {
namespace AppExecFwk {
class SignTools {
public:
    static bool VerifyFileSign(const std::string &pubKeyPath, const std::string &singPath,
        const std::string &digestPath);
    static std::tuple<int, std::string> CalcFileSha256Digest(const std::string &fpath);

private:
    static int ForEachFileSegment(const std::string &fpath, std::function<void(char *, size_t)> executor);
    static void CalcBase64(uint8_t *input, uint32_t inputLen, std::string &encodedStr);
    static bool VerifyRsa(RSA *rsa, const std::string &digest, const std::string &sign);
    static std::string GetfileStream(const std::string &filepath);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_SIGN_TOOLS_H