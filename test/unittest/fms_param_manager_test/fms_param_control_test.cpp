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
#include <gtest/gtest.h>
#include "form_constants.h"
#include "feature/param_update/param_control.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class FmsParamControlTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    ParamControl& paramControl = ParamControl::GetInstance();
};

void FmsParamControlTest::SetUp()
{}

void FmsParamControlTest::TearDown()
{}

/**
 * @tc.name: fmsParamControl_001
 * @tc.desc: test DealDueParam function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_001 start";
    std::string jsonStr = "";
    paramControl.DealDueParam(jsonStr);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_001 end";
}

/**
 * @tc.name: fmsParamControl_002
 * @tc.desc: test GetDueUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_002 start";
    FormRecord formRecord;
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_002 end";
}

/**
 * @tc.name: fmsParamControl_003
 * @tc.desc: test GetDueUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_003 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":[{\"bundleName\":\"com.example.duedemo\",\"moduleName\":\"entry\",\"abilityName\":\"EntryFormAbility\",\"formName\":\"widget1\",\"dimension\":[2],\"appVersionStart\":0,\"appVersionEnd\":0,\"updateDuration\":0}]}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord;
    formRecord.bundleName = "com.example.duedemo";
    formRecord.moduleName = "entry";
    formRecord.abilityName = "EntryFormAbility";
    formRecord.formName = "widget";
    formRecord.specification = 2;
    formRecord.versionCode = 1;
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);

    formRecord.formName = "widget1";
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 0);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_003 end";
}

/**
 * @tc.name: fmsParamControl_004
 * @tc.desc: test IsFormDisable、IsFormRemove function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_004 start";
    FormRecord formRecord;
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));

    std::string jsonStr = "{\"formDisableCtrl\":[{\"bundleName\":\"com.example.duedemo\",\"moduleName\":\"entry\",\"abilityName\":\"EntryFormAbility\",\"formName\":\"widget2\",\"dimension\":[2],\"appVersionStart\":0,\"appVersionEnd\":0,\"policy\":\"remove\"}]}";
    paramControl.DealDueParam(jsonStr);
    formRecord.bundleName = "com.example.duedemo";
    formRecord.moduleName = "entry";
    formRecord.abilityName = "EntryFormAbility";
    formRecord.formName = "widget2";
    formRecord.specification = 2;
    formRecord.versionCode = 1;
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));

    jsonStr = "{\"formDisableCtrl\":[{\"bundleName\":\"com.example.duedemo\",\"moduleName\":\"entry\",\"abilityName\":\"EntryFormAbility\",\"formName\":\"widget2\",\"dimension\":[2],\"appVersionStart\":0,\"appVersionEnd\":0,\"policy\":\"disable\"}]}";
    paramControl.DealDueParam(jsonStr);
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_004 end";
}

/**
 * @tc.name: fmsParamControl_005
 * @tc.desc: test ReloadDueControlByAppUpgrade function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_005 start";
    std::vector<FormRecord> updateFormRecords;
    paramControl.ReloadDueControlByAppUpgrade(updateFormRecords);
    FormRecord formRecord;
    updateFormRecords.push_back(formRecord);
    paramControl.ReloadDueControlByAppUpgrade(updateFormRecords);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_005 end";
}
} // namespace AppExecFwk
} // namespace OHOS