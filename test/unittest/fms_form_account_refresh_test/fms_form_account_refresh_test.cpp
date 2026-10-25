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

// Task 1: Constants definition
HWTEST_F(FmsFormAccountRefreshTest, TestConstants_001, TestSize.Level0)
{
    EXPECT_EQ(Constants::CONDITION_NETWORK, 1);
    EXPECT_EQ(Constants::CONDITION_ACCOUNT, 3);
    EXPECT_EQ(Constants::REFRESHTYPE_ACCOUNT_CHANGED, 6);
}

// Task 1: CONDITION_REFRESHTYPE_SET
HWTEST_F(FmsFormAccountRefreshTest, TestConditionRefreshTypeSet_001, TestSize.Level0)
{
    EXPECT_TRUE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_NETWORKCHANGED) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
    EXPECT_TRUE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_ACCOUNT_CHANGED) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
    EXPECT_FALSE(Constants::CONDITION_REFRESHTYPE_SET.find(Constants::REFRESHTYPE_HOST) !=
        Constants::CONDITION_REFRESHTYPE_SET.end());
}

// Task 2: FormRefreshType enum
HWTEST_F(FmsFormAccountRefreshTest, TestFormRefreshType_001, TestSize.Level0)
{
    EXPECT_EQ(FormRefreshType::TYPE_ACCOUNT, 10);
}

// Task 3: IsConditionRefreshType
HWTEST_F(FmsFormAccountRefreshTest, TestIsConditionRefreshType_001, TestSize.Level0)
{
    EXPECT_TRUE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_NETWORKCHANGED));
    EXPECT_TRUE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_ACCOUNT_CHANGED));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_HOST));
    EXPECT_FALSE(FormConstantsUtil::IsConditionRefreshType(Constants::REFRESHTYPE_DEFAULT));
}

// Task 5: IsAccountConditionForm with isSystemApp double-insurance
HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_001, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {Constants::CONDITION_ACCOUNT};
    EXPECT_TRUE(FormDataMgr::IsAccountConditionForm(record));
}

HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_002, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = false;  // non-system app blocked
    record.conditionUpdate = {Constants::CONDITION_ACCOUNT};
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}

HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_003, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {Constants::CONDITION_NETWORK};  // no CONDITION_ACCOUNT
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}

HWTEST_F(FmsFormAccountRefreshTest, TestIsAccountConditionForm_004, TestSize.Level0)
{
    FormRecord record;
    record.isSystemApp = true;
    record.conditionUpdate = {};  // empty conditionUpdate
    EXPECT_FALSE(FormDataMgr::IsAccountConditionForm(record));
}

// Task 5: GetFormRecordByCondition userId overload conditionType assertion
HWTEST_F(FmsFormAccountRefreshTest, TestGetFormRecordByCondition_Q3B_001, TestSize.Level0)
{
    std::vector<FormRecord> formInfos;
    // Non-CONDITION_ACCOUNT type returns false
    bool result = FormDataMgr::GetInstance().GetFormRecordByCondition(
        Constants::CONDITION_NETWORK, 100, formInfos);
    EXPECT_FALSE(result);
}

HWTEST_F(FmsFormAccountRefreshTest, TestGetFormRecordByCondition_Q3B_002, TestSize.Level0)
{
    std::vector<FormRecord> formInfos;
    // CONDITION_ACCOUNT with non-existent userId returns false (no matching records)
    bool result = FormDataMgr::GetInstance().GetFormRecordByCondition(
        Constants::CONDITION_ACCOUNT, 99999, formInfos);
    EXPECT_FALSE(result);
}
