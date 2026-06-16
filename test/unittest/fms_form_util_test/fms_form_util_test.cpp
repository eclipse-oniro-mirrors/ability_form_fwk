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
#include <ctime>
#define private public
#include "common/util/form_util.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "os_account_manager_wrapper.h"
#undef private
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormUtilTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormUtilTest::SetUpTestCase()
{}

void FormUtilTest::TearDownTestCase()
{}

void FormUtilTest::SetUp()
{}

void FormUtilTest::TearDown()
{}

namespace {
    bool g_mockQueryActiveOsAccountIdsRetVal = true;
    bool g_mockQueryActiveOsAccountIdsParams = false;
}

void MockQueryActiveOsAccountIdsRetVal(bool mockRet)
{
    g_mockQueryActiveOsAccountIdsRetVal = mockRet;
}

void MockQueryActiveOsAccountIdsParams(bool mockRet)
{
    g_mockQueryActiveOsAccountIdsParams = mockRet;
}

ErrCode OsAccountManagerWrapper::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    if (g_mockQueryActiveOsAccountIdsParams) {
        ids.push_back(99);
    }
    return g_mockQueryActiveOsAccountIdsRetVal ? ERR_OK : ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

/**
 * @tc.name: FormUtilTest_001
 * @tc.desc: Verify GenerateFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_001, TestSize.Level0)
{
    constexpr int64_t udidHash = 0x1111111100000000L;
    const int64_t result = FormUtil::GenerateFormId(udidHash);

    EXPECT_EQ(udidHash, (udidHash & result));
}

/**
 * @tc.name: FormUtilTest_002
 * @tc.desc: Verify PaddingUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_002, TestSize.Level1)
{
    constexpr uint64_t formId = 0x1111111100000000L;
    constexpr uint64_t udidHash = 0x0000000011111111L;
    const int64_t result = FormUtil::PaddingUdidHash(formId, udidHash);

    EXPECT_EQ(result, formId);
}

/**
 * @tc.name: FormUtilTest_003
 * @tc.desc: Verify PaddingUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_003, TestSize.Level1)
{
    constexpr uint64_t formId = 0x0000000011111111L;
    constexpr uint64_t udidHash = 0x1111111100000000L;
    const int64_t result = FormUtil::PaddingUdidHash(formId, udidHash);

    EXPECT_EQ(result, udidHash | formId);
}

/**
 * @tc.name: FormUtilTest_004
 * @tc.desc: Verify GenerateUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_004, TestSize.Level1)
{
    int64_t udidHash = 0x1111111100000000L;
    auto result = FormUtil::GenerateUdidHash(udidHash);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FormUtilTest_005
 * @tc.desc: Verify GenerateUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_005, TestSize.Level1)
{
    int64_t udidHash = 0;
    auto result = FormUtil::GenerateUdidHash(udidHash);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FormUtilTest_006
 * @tc.desc: Verify GetCurrentNanosecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_006, TestSize.Level1)
{
    auto result1 = FormUtil::GetCurrentNanosecond();
    auto result2 = FormUtil::GetCurrentNanosecond();

    EXPECT_TRUE(result2 >= result1);
}

/**
 * @tc.name: FormUtilTest_007
 * @tc.desc: Verify GetCurrentMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_007, TestSize.Level1)
{
    auto result1 = FormUtil::GetCurrentMillisecond();
    auto result2 = FormUtil::GetCurrentMillisecond();

    EXPECT_TRUE(result2 >= result1);
}

/**
 * @tc.name: FormUtilTest_008
 * @tc.desc: Verify GetMillisecondFromTm
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_008, TestSize.Level1)
{
    constexpr int64_t value = -1;
    time_t rawtime;
    time(&rawtime);
    struct tm* timeinfo = localtime(&rawtime);
    EXPECT_TRUE(timeinfo != nullptr);

    auto result = FormUtil::GetMillisecondFromTm(*timeinfo);

    EXPECT_NE(result, value);
}

/**
 * @tc.name: FormUtilTest_009
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_009, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(false);
    MockQueryActiveOsAccountIdsParams(false);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_NE(result, accountId);
}

/**
 * @tc.name: FormUtilTest_010
 * @tc.desc: Verify StringSplit
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_010, TestSize.Level1)
{
    constexpr size_t count = 3;
    const std::string str = "10:35:27";
    auto result = FormUtil::StringSplit(str, Constants::TIME_DELIMETER);

    EXPECT_TRUE(result.size() == count);
}

/**
 * @tc.name: FormUtilTest_011
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_011, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(true);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_EQ(result, accountId);
}

/**
 * @tc.name: FormUtilTest_012
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_012, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(false);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_NE(result, accountId);
}

/**
 * @tc.name: FormUtilTest_014
 * @tc.desc: Verify IsActiveUser
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_014, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(true);
    EXPECT_EQ(true, FormUtil::IsActiveUser(accountId));
 
    MockQueryActiveOsAccountIdsRetVal(false);
    MockQueryActiveOsAccountIdsParams(false);
    EXPECT_EQ(false, FormUtil::IsActiveUser(accountId));
}

/**
 * @tc.name: FormUtilTest_015
 * @tc.desc: Verify GetActiveUsers
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_015, TestSize.Level1)
{
    std::vector<int32_t> activeList;
    FormUtil::GetActiveUsers(activeList);
    EXPECT_EQ(true, activeList.empty());
}

/**
 * @tc.name: FormUtilTest_016
 * @tc.desc: Verify GenerateFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_016, TestSize.Level1)
{
    constexpr int64_t udidHash = 0x00000000ffffffffL;
    int64_t firstFormId = FormUtil::GenerateFormId(udidHash);
    int64_t secondFormId = FormUtil::GenerateFormId(udidHash);
    EXPECT_EQ(firstFormId, secondFormId);
    FormUtil::DeleteFormId(firstFormId);
    FormUtil::DeleteFormId(secondFormId);
}

/**
 * @tc.name: FormUtilTest_017
 * @tc.desc: Verify ConvertStringToInt64 with 19-digit number starting with 8
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_017, TestSize.Level1)
{
    std::string strInfo = "8223372036854775807";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_TRUE(result);
    EXPECT_EQ(int64Value, 8223372036854775807);
}

/**
 * @tc.name: FormUtilTest_018
 * @tc.desc: Verify ConvertStringToInt64 with number exceeding INT64_MAX
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_018, TestSize.Level1)
{
    std::string strInfo = "9234567890123456789";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: FormUtilTest_019
 * @tc.desc: Verify ConvertStringToInt64 with negative number
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_019, TestSize.Level1)
{
    std::string strInfo = "-123";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_TRUE(result);
    EXPECT_EQ(int64Value, -123);
}

/**
 * @tc.name: FormUtilTest_020
 * @tc.desc: Verify ConvertStringToInt64 with short negative number
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_020, TestSize.Level1)
{
    std::string strInfo = "-456";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_TRUE(result);
    EXPECT_EQ(int64Value, -456);
}

/**
 * @tc.name: FormUtilTest_021
 * @tc.desc: Verify ConvertStringToInt64 with 20-digit negative number
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_021, TestSize.Level1)
{
    std::string strInfo = "-9223372036854775808";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_TRUE(result);
    EXPECT_EQ(int64Value, -9223372036854775807 - 1);
}

/**
 * @tc.name: FormUtilTest_022
 * @tc.desc: Verify ConvertStringToInt64 with 20-digit negative starting with -8
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_022, TestSize.Level1)
{
    std::string strInfo = "-8223372036854775808";
    int64_t int64Value = 0;
    auto result = FormUtil::ConvertStringToInt64(strInfo, int64Value);
    EXPECT_TRUE(result);
}

}  // namespace AppExecFwk
}  // namespace OHOS