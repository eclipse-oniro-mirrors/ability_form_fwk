/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private public
#include "data_center/database/form_db_info.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
const int64_t FORM_ID = 3;
const int64_t USER_ID = 10;

namespace {
class FmsFormDbInfoTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FmsFormDbInfoTest::SetUpTestCase() {}

void FmsFormDbInfoTest::TearDownTestCase() {}

void FmsFormDbInfoTest::SetUp() {}

void FmsFormDbInfoTest::TearDown() {}

FormDBInfo CreateDbInfo()
{
    FormDBInfo info;
    info.formId = FORM_ID;
    info.userId = USER_ID;
    info.providerUserId = USER_ID;
    info.formName = "test_form";
    info.bundleName = "test_bundle";
    info.moduleName = "test_module";
    info.abilityName = "test_ability";
    info.formUserUids = {20241010, 20241011};
    info.formLocation = Constants::FormLocation::SCREEN_LOCK;
    info.isThemeForm = true;
    info.enableForm = true;
    return info;
}

/**
 * @tc.name: FmsFormDbInfoTest_0001
 * @tc.desc: Fun constructor.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0001 start";
    int64_t formId{ 1 };
    int32_t userId{ 2 };
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.userId = userId;
    formRecord.formName = "test";
    FormDBInfo info(formId, formRecord);
    EXPECT_EQ(info.formId, formRecord.formId);
    EXPECT_EQ(info.userId, formRecord.userId);
    EXPECT_EQ(info.formName, formRecord.formName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0001 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0002
 * @tc.desc: Fun Contains.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0002 start";
    int32_t user = 10;
    FormDBInfo info = CreateDbInfo();
    EXPECT_FALSE(info.Contains(user));
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0002 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0003
 * @tc.desc: Fun Compare.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0003 start";
    FormDBInfo info1 = CreateDbInfo();
    FormDBInfo info2 = CreateDbInfo();
    EXPECT_TRUE(info1.Compare(info2));
    info2.bundleName = "test";
    EXPECT_FALSE(info1.Compare(info2));
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0003 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0004
 * @tc.desc: Fun ToJson.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0004 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    nlohmann::json jInfo;
    innerInfo.ToJson(jInfo);
    EXPECT_EQ(jInfo["formName"], innerInfo.GetFormName());
    EXPECT_EQ(jInfo["bundleName"], innerInfo.GetBundleName());
    EXPECT_EQ(jInfo["abilityName"], innerInfo.GetAbilityName());
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0004 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0005
 * @tc.desc: Fun SetFormName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0005 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetFormName("test002");
    EXPECT_NE(innerInfo.GetFormName(), info.formName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0005 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0006
 * @tc.desc: Fun AddUserUid.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0006 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    innerInfo.AddUserUid(20241011);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0006 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0007
 * @tc.desc: Fun AddUserUid.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0007 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    innerInfo.AddUserUid(20241012);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 3);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0007 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0008
 * @tc.desc: Fun DeleteUserUid.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0008 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    innerInfo.DeleteUserUid(20241011);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0008 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0009
 * @tc.desc: Fun DeleteUserUid.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0009 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    innerInfo.DeleteUserUid(20241012);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0009 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0010
 * @tc.desc: Fun GetFormId.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0010 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetFormId(), info.formId);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0010 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0011
 * @tc.desc: Fun SetFormId.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0011 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetFormId(11);
    EXPECT_NE(innerInfo.GetFormId(), info.formId);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0011 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0012
 * @tc.desc: Fun GetUserId.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0012 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetUserId(), info.userId);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0012 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0013
 * @tc.desc: Fun SetUserId.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0013 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetUserId(6);
    EXPECT_NE(innerInfo.GetUserId(), info.userId);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0013 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0014
 * @tc.desc: Fun GetModuleName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0014 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetModuleName(), info.moduleName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0014 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0015
 * @tc.desc: Fun SetModuleName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0015 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetModuleName("test001");
    EXPECT_NE(innerInfo.GetModuleName(), info.moduleName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0015 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0016
 * @tc.desc: Fun GetBundleName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0016 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetBundleName(), info.bundleName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0016 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0017
 * @tc.desc: Fun SetBundleName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0017 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetBundleName("bundle001");
    EXPECT_NE(innerInfo.GetBundleName(), info.bundleName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0017 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0018
 * @tc.desc: Fun GetAbilityName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0018 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetAbilityName(), info.abilityName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0018 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0019
 * @tc.desc: Fun SetAbilityName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0019 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetAbilityName("ability001");
    EXPECT_NE(innerInfo.GetAbilityName(), info.abilityName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0019 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0020
 * @tc.desc: Fun SetUserUids.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0020 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 2);
    innerInfo.SetUserUids({20241011, 20241013});
    EXPECT_EQ(innerInfo.formDBInfo_.formUserUids.size(), 4);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0020 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0021
 * @tc.desc: Fun SetFormDBInfo.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0021 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo;
    innerInfo.SetFormDBInfo(info);
    EXPECT_TRUE(innerInfo.formDBInfo_.Compare(info));
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0021 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0022
 * @tc.desc: Fun GetFormDBInfo.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0022 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    auto innerDbInfo = innerInfo.GetFormDBInfo();
    EXPECT_TRUE(info.Compare(innerDbInfo));
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0022 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0023
 * @tc.desc: Fun GetUserUids.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0023 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    auto uids = innerInfo.GetUserUids();
    EXPECT_TRUE(uids.size() == 2);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0023 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0024
 * @tc.desc: Fun SetIsThemeForm.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0024 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetIsThemeForm(false);
    EXPECT_NE(innerInfo.GetIsThemeForm(), info.isThemeForm);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0024 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0025
 * @tc.desc: Fun GetIsThemeForm.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0025 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetIsThemeForm(), info.isThemeForm);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0025 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0026
 * @tc.desc: Fun IsEnableForm.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0026 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.IsEnableForm(), info.enableForm);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0026 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0027
 * @tc.desc: Fun SetEnableForm.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0027 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    innerInfo.SetEnableForm(false);
    EXPECT_NE(innerInfo.IsEnableForm(), info.enableForm);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0027 end";
}

/**
 * @tc.name: FmsFormDbInfoTest_0028
 * @tc.desc: Fun GetFormName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbInfoTest, FmsFormDbInfoTest_0028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0028 start";
    FormDBInfo info = CreateDbInfo();
    InnerFormInfo innerInfo(info);
    EXPECT_EQ(innerInfo.GetFormName(), info.formName);
    GTEST_LOG_(INFO) << "FmsFormDbInfoTest_FmsFormDbInfoTest_0028 end";
}
}
