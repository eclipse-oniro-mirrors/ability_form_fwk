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

#include "form_constants.h"
#include "form_constants_util.h"
#include "form_refresh/form_refresh_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_record/form_record.h"

using namespace testing;
using namespace OHOS::AppExecFwk;

class FmsFormAccountRefreshTest : public Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

/**
 * @tc.number: FmsFormAccountRefreshTest_Constants_001
 * @tc.name: Constants definition
 * @tc.desc: Verify account-refresh related constants are defined with expected values.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestConstants_001, TestSize.Level0)
{
    EXPECT_EQ(Constants::CONDITION_NETWORK, 1);
    EXPECT_EQ(Constants::CONDITION_ACCOUNT, 3);
    EXPECT_EQ(Constants::REFRESHTYPE_ACCOUNT_CHANGED, 6);
}

/**
 * @tc.number: FmsFormAccountRefreshTest_ConditionRefreshTypeSet_001
 * @tc.name: CONDITION_REFRESHTYPE_SET membership
 * @tc.desc: Verify the set contains network and account refresh types and excludes others.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestConditionRefreshTypeSet_001, TestSize.Level0)
{
    EXPECT_TRUE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_NETWORKCHANGED) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
    EXPECT_TRUE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_ACCOUNT_CHANGED) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
    EXPECT_FALSE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_HOST) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
}

/**
 * @tc.number: FmsFormAccountRefreshTest_FormRefreshType_001
 * @tc.name: FormRefreshType enum
 * @tc.desc: Verify TYPE_ACCOUNT enum value.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestFormRefreshType_001, TestSize.Level0)
{
    EXPECT_EQ(FormRefreshType::TYPE_ACCOUNT, 10);
}

/**
 * @tc.number: FmsFormAccountRefreshTest_IsConditionRefreshType_001
 * @tc.name: IsConditionRefreshType
 * @tc.desc: Verify IsConditionRefreshType returns true for network/account, false for others.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestIsConditionRefreshType_001, TestSize.Level0)
{
    EXPECT_TRUE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_NETWORKCHANGED));
    EXPECT_TRUE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_ACCOUNT_CHANGED));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_HOST));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_DEFAULT));
}

/**
 * @tc.number: FmsFormAccountRefreshTest_IsAccountConditionForm_001
 * @tc.name: IsAccountConditionForm system app with account condition
 * @tc.desc: Verify system app record with CONDITION_ACCOUNT returns true.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_001, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {Constants::CONDITION_ACCOUNT};
    EXPECT_TRUE(FormDataMgr::IsAccountConditionForm(record));
}

/**
 * @tc.number: FmsFormAccountRefreshTest_IsAccountConditionForm_002
 * @tc.name: IsAccountConditionForm non-system app blocked
 * @tc.desc: Verify non-system app record with CONDITION_ACCOUNT returns false (double-insurance).
 */
HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_002, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = false;  // non-system app blocked
    record.conditionUpdate = {Constants::CONDITION_ACCOUNT};
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}

/**
 * @tc.number: FmsFormAccountRefreshTest_IsAccountConditionForm_003
 * @tc.name: IsAccountConditionForm without account condition
 * @tc.desc: Verify system app record with only network condition returns false.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_003, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {Constants::CONDITION_NETWORK};  // no CONDITION_ACCOUNT
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}

/**
 * @tc.number: FmsFormAccountRefreshTest_IsAccountConditionForm_004
 * @tc.name: IsAccountConditionForm empty conditionUpdate
 * @tc.desc: Verify system app record with empty conditionUpdate returns false.
 */
HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_004, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {};  // empty conditionUpdate
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}