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
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "feature/param_update/sign_tools.h"
#include "common/util/file_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

namespace {
    const std::string TEST_DIR = "/data/test/sign_tools_test/";
    const std::string PUBKEY_FILE = TEST_DIR + "test_pubkey.pem";
    const std::string SIGN_FILE = TEST_DIR + "test_sign.sig";
    const std::string DIGEST_FILE = TEST_DIR + "test_digest.txt";
    const std::string TEST_FILE = TEST_DIR + "test_file.txt";
    const std::string NON_EXIST_FILE = "/non/exist/file.txt";
}

class FmsSignToolsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void FmsSignToolsTest::SetUpTestCase(void)
{
    int ret = system(std::string("mkdir -p " + TEST_DIR).c_str());
    if (ret != 0) {
        FAIL() << "Failed to create test directory: " << TEST_DIR;
    }
    
    std::ofstream pubKeyFile(PUBKEY_FILE);
    if (!pubKeyFile.is_open()) {
        FAIL() << "Failed to open pubkey file: " << PUBKEY_FILE;
    }
    pubKeyFile << "-----BEGIN RSA PUBLIC KEY-----\n";
    pubKeyFile << "MIIBCgKCAQEAwVxPbKZgYK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8s\n";
    pubKeyFile << "N+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDk\n";
    pubKeyFile << "P6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8\n";
    pubKeyFile << "YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8\n";
    pubKeyFile << "sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQD\n";
    pubKeyFile << "kP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK\n";
    pubKeyFile << "8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8\n";
    pubKeyFile << "sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQDkP6QdR+8sN+3FvK8YvO4VvQD\n";
    pubKeyFile << "kP6QdR+8sN+3FwIDAQAB\n";
    pubKeyFile << "-----END RSA PUBLIC KEY-----\n";
    pubKeyFile.close();
    
    std::ofstream signFile(SIGN_FILE);
    if (!signFile.is_open()) {
        FAIL() << "Failed to open sign file: " << SIGN_FILE;
    }
    signFile << "testsigndata";
    signFile.close();
    
    std::ofstream digestFile(DIGEST_FILE);
    if (!digestFile.is_open()) {
        FAIL() << "Failed to open digest file: " << DIGEST_FILE;
    }
    digestFile << "testdigestdata";
    digestFile.close();
    
    std::ofstream testFile(TEST_FILE);
    if (!testFile.is_open()) {
        FAIL() << "Failed to open test file: " << TEST_FILE;
    }
    testFile << "This is test content for SHA256 calculation\n";
    testFile.close();
}

void FmsSignToolsTest::TearDownTestCase(void)
{
    int ret = system(std::string("rm -rf " + TEST_DIR).c_str());
    if (ret != 0) {
        GTEST_LOG_(ERROR) << "Failed to remove test directory: " << TEST_DIR;
    }
}

void FmsSignToolsTest::SetUp(void)
{
}

void FmsSignToolsTest::TearDown(void)
{
}

/**
 * @tc.name: VerifyFileSign_001
 * @tc.desc: Verify pubKey file not exist returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_001 start";
    
    auto result = SignTools::VerifyFileSign(NON_EXIST_FILE, SIGN_FILE, DIGEST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_001 end";
}

/**
 * @tc.name: VerifyFileSign_002
 * @tc.desc: Verify sign file not exist returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_002 start";
    
    auto result = SignTools::VerifyFileSign(PUBKEY_FILE, NON_EXIST_FILE, DIGEST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_002 end";
}

/**
 * @tc.name: VerifyFileSign_003
 * @tc.desc: Verify digest file not exist returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_003 start";
    
    auto result = SignTools::VerifyFileSign(PUBKEY_FILE, SIGN_FILE, NON_EXIST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_003 end";
}

/**
 * @tc.name: VerifyFileSign_004
 * @tc.desc: Verify PEM_read_bio_RSA_PUBKEY fails returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_004 start";
    
    std::string invalidPubKey = TEST_DIR + "invalid_pubkey.pem";
    std::ofstream invalidFile(invalidPubKey);
    invalidFile << "INVALID_KEY_CONTENT";
    invalidFile.close();
    
    auto result = SignTools::VerifyFileSign(invalidPubKey, SIGN_FILE, DIGEST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_004 end";
}

/**
 * @tc.name: VerifyFileSign_005
 * @tc.desc: Verify all files exist but invalid signature returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_005 start";
    
    auto result = SignTools::VerifyFileSign(PUBKEY_FILE, SIGN_FILE, DIGEST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_005 end";
}

/**
 * @tc.name: VerifyFileSign_006
 * @tc.desc: Verify empty sign file returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, VerifyFileSign_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "VerifyFileSign_006 start";
    
    std::string emptySign = TEST_DIR + "empty_sign.sig";
    std::ofstream emptyFile(emptySign);
    emptyFile.close();
    
    auto result = SignTools::VerifyFileSign(PUBKEY_FILE, emptySign, DIGEST_FILE);
    EXPECT_FALSE(result);
    
    GTEST_LOG_(INFO) << "VerifyFileSign_006 end";
}

/**
 * @tc.name: CalcFileSha256Digest_001
 * @tc.desc: Verify file not exist returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, CalcFileSha256Digest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_001 start";
    
    auto [err, digest] = SignTools::CalcFileSha256Digest(NON_EXIST_FILE);
    EXPECT_NE(err, 0);
    EXPECT_TRUE(digest.empty());
    
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_001 end";
}

/**
 * @tc.name: CalcFileSha256Digest_002
 * @tc.desc: Verify file exists and calculation success
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, CalcFileSha256Digest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_002 start";
    
    auto [err, digest] = SignTools::CalcFileSha256Digest(TEST_FILE);
    EXPECT_EQ(err, 0);
    EXPECT_FALSE(digest.empty());
    
    GTEST_LOG_(INFO) << "Digest: " << digest;
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_002 end";
}

/**
 * @tc.name: CalcFileSha256Digest_003
 * @tc.desc: Verify empty file returns fixed SHA256 digest
 *           (sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, CalcFileSha256Digest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_003 start";
    
    std::string emptyFile = TEST_DIR + "empty_file.txt";
    std::ofstream empty(emptyFile);
    empty.close();
    
    auto [err, digest] = SignTools::CalcFileSha256Digest(emptyFile);
    EXPECT_EQ(err, 0);
    EXPECT_FALSE(digest.empty());
    EXPECT_EQ(digest, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_003 end";
}

/**
 * @tc.name: CalcFileSha256Digest_004
 * @tc.desc: Verify large file calculation success
 * @tc.type: FUNC
 */
HWTEST_F(FmsSignToolsTest, CalcFileSha256Digest_004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_004 start";
    
    std::string largeFile = TEST_DIR + "large_file.txt";
    std::ofstream large(largeFile);
    if (!large.is_open()) {
        FAIL() << "Failed to open large file: " << largeFile;
    }
    for (int i = 0; i < 1000; i++) {
        large << "Line " << i << ": This is test content for large file\n";
    }
    large.close();
    
    auto [err, digest] = SignTools::CalcFileSha256Digest(largeFile);
    EXPECT_EQ(err, 0);
    EXPECT_FALSE(digest.empty());
    
    GTEST_LOG_(INFO) << "CalcFileSha256Digest_004 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS