/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
 * @tc.name: FormUtilTest_004
 * @tc.desc: Verify GenerateFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_004, TestSize.Level1)
{
    constexpr int64_t udidHash = 0x1111111100000000L;
    const int64_t result = FormUtil::GenerateFormId(udidHash);

    EXPECT_EQ(udidHash, (udidHash & result));
}

/**
 * @tc.name: FormUtilTest_005
 * @tc.desc: Verify PaddingUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_005, TestSize.Level1)
{
    constexpr uint64_t formId = 0x1111111100000000L;
    constexpr uint64_t udidHash = 0x0000000011111111L;
    const int64_t result = FormUtil::PaddingUdidHash(formId, udidHash);

    EXPECT_EQ(result, formId);
}

/**
 * @tc.name: FormUtilTest_006
 * @tc.desc: Verify PaddingUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_006, TestSize.Level1)
{
    constexpr uint64_t formId = 0x0000000011111111L;
    constexpr uint64_t udidHash = 0x1111111100000000L;
    const int64_t result = FormUtil::PaddingUdidHash(formId, udidHash);

    EXPECT_EQ(result, udidHash | formId);
}

/**
 * @tc.name: FormUtilTest_007
 * @tc.desc: Verify GenerateUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_007, TestSize.Level1)
{
    int64_t udidHash = 0x1111111100000000L;
    auto result = FormUtil::GenerateUdidHash(udidHash);
    EXPECT_TRUE(result);

    udidHash = 0xFFFFL;
    result = FormUtil::GenerateUdidHash(udidHash);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: FormUtilTest_008
 * @tc.desc: Verify GenerateUdidHash
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_008, TestSize.Level1)
{
    int64_t udidHash = 0;
    auto result = FormUtil::GenerateUdidHash(udidHash);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: FormUtilTest_009
 * @tc.desc: Verify GetCurrentNanosecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_009, TestSize.Level1)
{
    auto result1 = FormUtil::GetCurrentNanosecond();
    auto result2 = FormUtil::GetCurrentNanosecond();

    EXPECT_TRUE(result2 >= result1);
}

/**
 * @tc.name: FormUtilTest_010
 * @tc.desc: Verify GetCurrentMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_010, TestSize.Level1)
{
    auto result1 = FormUtil::GetCurrentMillisecond();
    auto result2 = FormUtil::GetCurrentMillisecond();

    EXPECT_TRUE(result2 >= result1);
}

/**
 * @tc.name: FormUtilTest_011
 * @tc.desc: Verify GetMillisecondFromTm
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_011, TestSize.Level1)
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
 * @tc.name: FormUtilTest_012
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_012, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(false);
    MockQueryActiveOsAccountIdsParams(false);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_NE(result, accountId);
}

/**
 * @tc.name: FormUtilTest_013
 * @tc.desc: Verify StringSplit
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_013, TestSize.Level1)
{
    constexpr size_t count = 3;
    const std::string str = "10:35:27";
    auto result = FormUtil::StringSplit(str, Constants::TIME_DELIMETER);

    EXPECT_TRUE(result.size() == count);
    for (int i = 0; i < 42; ++i) {
        EXPECT_EQ(FormUtil::TestFormId1(i), i);
        EXPECT_EQ(FormUtil::TestFormId2(i), i);
        EXPECT_EQ(FormUtil::TestFormId3(i), i);
        EXPECT_EQ(FormUtil::TestFormId4(i), i);
        EXPECT_EQ(FormUtil::TestFormId5(i), i);
        EXPECT_EQ(FormUtil::TestFormId6(i), i);
        EXPECT_EQ(FormUtil::TestFormId7(i), i);
        EXPECT_EQ(FormUtil::TestFormId8(i), i);
        EXPECT_EQ(FormUtil::TestFormId9(i), i);
        EXPECT_EQ(FormUtil::TestFormId10(i), i);
        EXPECT_EQ(FormUtil::TestFormId11(i), i);
        EXPECT_EQ(FormUtil::TestFormId12(i), i);
        EXPECT_EQ(FormUtil::TestFormId13(i), i);
        EXPECT_EQ(FormUtil::TestFormId14(i), i);
        EXPECT_EQ(FormUtil::TestFormId15(i), i);
        EXPECT_EQ(FormUtil::TestFormId16(i), i);
        EXPECT_EQ(FormUtil::TestFormId17(i), i);
        EXPECT_EQ(FormUtil::TestFormId18(i), i);
        EXPECT_EQ(FormUtil::TestFormId19(i), i);
        EXPECT_EQ(FormUtil::TestFormId20(i), i);
        EXPECT_EQ(FormUtil::TestFormId21(i), i);
        EXPECT_EQ(FormUtil::TestFormId22(i), i);
        EXPECT_EQ(FormUtil::TestFormId23(i), i);
        EXPECT_EQ(FormUtil::TestFormId24(i), i);
        EXPECT_EQ(FormUtil::TestFormId25(i), i);
        EXPECT_EQ(FormUtil::TestFormId26(i), i);
        EXPECT_EQ(FormUtil::TestFormId27(i), i);
        EXPECT_EQ(FormUtil::TestFormId28(i), i);
        EXPECT_EQ(FormUtil::TestFormId29(i), i);
        EXPECT_EQ(FormUtil::TestFormId30(i), i);
        EXPECT_EQ(FormUtil::TestFormId31(i), i);
        EXPECT_EQ(FormUtil::TestFormId32(i), i);
        EXPECT_EQ(FormUtil::TestFormId33(i), i);
        EXPECT_EQ(FormUtil::TestFormId34(i), i);
        EXPECT_EQ(FormUtil::TestFormId35(i), i);
    }
}

/**
 * @tc.name: FormUtilTest_014
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_014, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(true);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_EQ(result, accountId);
}

/**
 * @tc.name: FormUtilTest_015
 * @tc.desc: Verify GetCurrentAccountId
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_015, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(false);

    auto result = FormUtil::GetCurrentAccountId();

    EXPECT_NE(result, accountId);
}

/**
 * @tc.name: FormUtilTest_016
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_016, TestSize.Level1)
{
    auto result1 = FormUtil::GetNowMillisecond();
    auto result2 = FormUtil::GetNowMillisecond();

    EXPECT_TRUE(result2 >= result1);
}

/**
 * @tc.name: FormUtilTest_017
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_017, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_018
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_018, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_019
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_019, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_020
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_020, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_021
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_021, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_022
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_022, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_023
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_023, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_024
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_024, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_025
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_025, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_026
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_026, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_027
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_027, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_028
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_028, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

/**
 * @tc.name: FormUtilTest_029
 * @tc.desc: Verify GetNowMillisecond
 * @tc.type: FUNC
 */
HWTEST_F(FormUtilTest, FormUtilTest_029, TestSize.Level1)
{
    std::string strInfo = "";
    int64_t int64Value = 1;
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "abcd";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "9234567890123456789";
    EXPECT_FALSE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-123";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-1234567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    EXPECT_TRUE(FormUtil::ConvertStringToInt64(strInfo, int64Value));

    strInfo = "-9134567890123456789";
    FormUtil::ConvertStringToInt64(strInfo, int64Value);
}

HWTEST_F(FormUtilTest, FormUtilTest_030, TestSize.Level1)
{
    constexpr size_t accountId = 99;
    MockQueryActiveOsAccountIdsRetVal(true);
    MockQueryActiveOsAccountIdsParams(true);
    EXPECT_EQ(true, FormUtil::IsActiveUser(accountId));
 
    MockQueryActiveOsAccountIdsRetVal(false);
    MockQueryActiveOsAccountIdsParams(false);
    EXPECT_EQ(false, FormUtil::IsActiveUser(accountId));
}

HWTEST_F(FormUtilTest, FormUtilTest_031, TestSize.Level1)
{
    std::vector<int32_t> activeList;
    FormUtil::GetActiveUsers(activeList);
    EXPECT_EQ(true, activeList.empty());
}
}  // namespace AppExecFwk
}  // namespace OHOS