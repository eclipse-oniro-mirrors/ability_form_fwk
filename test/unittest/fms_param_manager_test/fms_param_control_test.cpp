/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

    FormRecord CreateFormRecord(
        const std::string& bundleName = "com.example.duedemo",
        const std::string& moduleName = "entry",
        const std::string& abilityName = "",
        const std::string& formName = "",
        int32_t specification = 0,
        int32_t versionCode = 0,
        int32_t lastVersionCode = 0)
    {
        FormRecord formRecord;
        formRecord.bundleName = bundleName;
        formRecord.moduleName = moduleName;
        formRecord.abilityName = abilityName;
        formRecord.formName = formName;
        formRecord.specification = specification;
        formRecord.versionCode = versionCode;
        formRecord.lastVersionCode = lastVersionCode;
        return formRecord;
    }

    std::string CreateUpdateDurationJson(
        const std::string& bundleName = "com.example.duedemo",
        const std::string& moduleName = "entry",
        const std::string& abilityName = "",
        const std::string& formName = "",
        const std::string& dimension = "",
        int32_t appVersionStart = 0,
        int32_t appVersionEnd = 0,
        int32_t updateDuration = 10)
    {
        std::string json = "{\"formUpdateDurationCtrl\":[{\"bundleName\":\"" + bundleName + "\","
            "\"moduleName\":\"" + moduleName + "\"";
        if (!abilityName.empty()) {
            json += ",\"abilityName\":\"" + abilityName + "\"";
        }
        if (!formName.empty()) {
            json += ",\"formName\":\"" + formName + "\"";
        }
        if (!dimension.empty()) {
            json += ",\"dimension\":[" + dimension + "]";
        }
        if (appVersionStart != 0 || appVersionEnd != 0) {
            json += ",\"appVersionStart\":" + std::to_string(appVersionStart) +
                ",\"appVersionEnd\":" + std::to_string(appVersionEnd);
        }
        json += ",\"updateDuration\":" + std::to_string(updateDuration) + "}]}";
        return json;
    }

    std::string CreateDisableCtrlJson(
        const std::string& bundleName = "com.example.duedemo",
        const std::string& moduleName = "entry",
        const std::string& abilityName = "",
        const std::string& formName = "",
        const std::string& dimension = "",
        int32_t appVersionStart = 0,
        int32_t appVersionEnd = 0,
        const std::string& policy = "disable")
    {
        std::string json = "{\"formDisableCtrl\":[{\"bundleName\":\"" + bundleName + "\","
            "\"moduleName\":\"" + moduleName + "\"";
        if (!abilityName.empty()) {
            json += ",\"abilityName\":\"" + abilityName + "\"";
        }
        if (!formName.empty()) {
            json += ",\"formName\":\"" + formName + "\"";
        }
        if (!dimension.empty()) {
            json += ",\"dimension\":[" + dimension + "]";
        }
        if (appVersionStart != 0 || appVersionEnd != 0) {
            json += ",\"appVersionStart\":" + std::to_string(appVersionStart) +
                ",\"appVersionEnd\":" + std::to_string(appVersionEnd);
        }
        json += ",\"policy\":\"" + policy + "\"}]}";
        return json;
    }
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
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFormRecord();
    int32_t durationBefore = paramControl.GetDueUpdateDuration(formRecord);
    std::string jsonStr = "";
    paramControl.DealDueParam(jsonStr);
    int32_t durationAfter = paramControl.GetDueUpdateDuration(formRecord);
    EXPECT_EQ(durationBefore, durationAfter);
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
    FormRecord formRecord = CreateFormRecord();
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_002 end";
}

HWTEST_F(FmsParamControlTest, fmsParamControl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_003 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":[{\"bundleName\":\"com.example.duedemo\","
        "\"moduleName\":\"entry\",\"abilityName\":\"EntryFormAbility\","
        "\"formName\":\"widget1\",\"dimension\":[2],\"appVersionStart\":0,"
        "\"appVersionEnd\":0,\"updateDuration\":0}]}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "EntryFormAbility", "widget", 2, 1);
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
    FormRecord formRecord = CreateFormRecord();
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));

    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "EntryFormAbility", "widget2",
        "2", 0, 0, "remove");
    paramControl.DealDueParam(jsonStr);
    formRecord = CreateFormRecord("com.example.duedemo", "entry", "EntryFormAbility", "widget2", 2, 1);
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));

    jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "EntryFormAbility", "widget2", "2", 0, 0,
        "disable");
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
    EXPECT_TRUE(updateFormRecords.empty());
    
    FormRecord formRecord = CreateFormRecord("com.example.test", "entry");
    updateFormRecords.push_back(formRecord);
    EXPECT_EQ(updateFormRecords.size(), 1);
    paramControl.ReloadDueControlByAppUpgrade(updateFormRecords);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_005 end";
}

/**
 * @tc.name: fmsParamControl_006
 * @tc.desc: test DealDueParam with invalid JSON.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_006 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFormRecord();
    int32_t durationBefore = paramControl.GetDueUpdateDuration(formRecord);
    std::string jsonStr = "invalid json string";
    paramControl.DealDueParam(jsonStr);
    int32_t durationAfter = paramControl.GetDueUpdateDuration(formRecord);
    EXPECT_EQ(durationBefore, durationAfter);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_006 end";
}

/**
 * @tc.name: fmsParamControl_007
 * @tc.desc: test DealDueParam with non-object JSON.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_007 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFormRecord();
    int32_t durationBefore = paramControl.GetDueUpdateDuration(formRecord);
    std::string jsonStr = "[1, 2, 3]";
    paramControl.DealDueParam(jsonStr);
    int32_t durationAfter = paramControl.GetDueUpdateDuration(formRecord);
    EXPECT_EQ(durationBefore, durationAfter);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_007 end";
}

/**
 * @tc.name: fmsParamControl_008
 * @tc.desc: test IsDueDisableCtrlEmpty function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_008 start";
    paramControl.DealDueParam("{}");
    EXPECT_TRUE(paramControl.IsDueDisableCtrlEmpty());
    
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 0, 0, "disable");
    paramControl.DealDueParam(jsonStr);
    EXPECT_FALSE(paramControl.IsDueDisableCtrlEmpty());
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_008 end";
}

/**
 * @tc.name: fmsParamControl_009
 * @tc.desc: test GetDueUpdateDuration with empty updateDurationCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_009 start";
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 1);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_009 end";
}

/**
 * @tc.name: fmsParamControl_010
 * @tc.desc: test DealDueParam with invalid param (empty bundleName).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_010 start";
    std::string jsonStr = CreateUpdateDurationJson("", "entry", "", "", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_010 end";
}

/**
 * @tc.name: fmsParamControl_011
 * @tc.desc: test DealDueParam with invalid param (empty moduleName).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_011 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "", "", "", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_011 end";
}

/**
 * @tc.name: fmsParamControl_012
 * @tc.desc: test DealDueParam with invalid param (appVersionStart > appVersionEnd).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_012 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 10, 5, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_012 end";
}

/**
 * @tc.name: fmsParamControl_013
 * @tc.desc: test DealDueParam with invalid updateDuration (negative).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_013 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 0, 0, -1);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 0);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_013 end";
}

/**
 * @tc.name: fmsParamControl_014
 * @tc.desc: test DealDueParam with invalid policy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_014 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 0, 0, "invalid");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_014 end";
}

/**
 * @tc.name: fmsParamControl_015
 * @tc.desc: test GetDueUpdateDuration with version range match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_015 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    
    formRecord.versionCode = 15;
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_015 end";
}

/**
 * @tc.name: fmsParamControl_016
 * @tc.desc: test IsFormDisable/IsFormRemove with version range match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_016 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 1, 10, "disable");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    
    formRecord.versionCode = 15;
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_016 end";
}

/**
 * @tc.name: fmsParamControl_017
 * @tc.desc: test IsFormInfoMatch with different bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_017 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.other", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_017 end";
}

/**
 * @tc.name: fmsParamControl_018
 * @tc.desc: test IsFormInfoMatch with different moduleName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_018 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "other");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_018 end";
}

/**
 * @tc.name: fmsParamControl_019
 * @tc.desc: test IsFormInfoMatch with abilityName mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_019 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "EntryFormAbility", "", "",
        0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "OtherAbility");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_019 end";
}

/**
 * @tc.name: fmsParamControl_020
 * @tc.desc: test IsFormInfoMatch with formName mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_020 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "widget1", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "widget2");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_020 end";
}

/**
 * @tc.name: fmsParamControl_021
 * @tc.desc: test IsFormInfoMatch with dimension mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_021 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "1,2", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 3);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_021 end";
}

/**
 * @tc.name: fmsParamControl_022
 * @tc.desc: test IsFormInfoMatch with zero version range.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_022 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 100);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 10);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_022 end";
}

/**
 * @tc.name: fmsParamControl_023
 * @tc.desc: versionCode == lastVersionCode.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_023 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    formRecord.lastVersionCode = 5;
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_023 end";
}

/**
 * @tc.name: fmsParamControl_024
 * @tc.desc: test DealDueParam with null formUpdateDurationCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_024 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":null}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord();
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_024 end";
}

/**
 * @tc.name: fmsParamControl_025
 * @tc.desc: test DealDueParam with non-array formUpdateDurationCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_025 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":\"not an array\"}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord();
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_025 end";
}

/**
 * @tc.name: fmsParamControl_026
 * @tc.desc: test DealDueParam with null formDisableCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_026 start";
    std::string jsonStr = "{\"formDisableCtrl\":null}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord();
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_026 end";
}

/**
 * @tc.name: fmsParamControl_027
 * @tc.desc: test DealDueParam with non-array formDisableCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_027 start";
    std::string jsonStr = "{\"formDisableCtrl\":\"not an array\"}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord();
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_027 end";
}

HWTEST_F(FmsParamControlTest, fmsParamControl_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_028 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":[{\"bundleName\":\""
        "com.example.duedemo\",\"moduleName\":\"entry\",\"updateDuration\":10}],"
        "\"formDisableCtrl\":[{\"bundleName\":\"com.example.duedemo\","
        "\"moduleName\":\"entry\",\"policy\":\"disable\"}]}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 10);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_028 end";
}

HWTEST_F(FmsParamControlTest, fmsParamControl_029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_029 start";
    std::string jsonStr = "{\"formUpdateDurationCtrl\":[{\"bundleName\":\""
        "com.example.duedemo\",\"moduleName\":\"entry\",\"updateDuration\":10},"
        "{\"bundleName\":\"com.example.other\",\"moduleName\":\"entry\","
        "\"updateDuration\":20}]}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 10);
    formRecord.bundleName = "com.example.other";
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_029 end";
}

/**
 * @tc.name: fmsParamControl_030
 * @tc.desc: test multiple items in formDisableCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_030 start";
    std::string jsonStr = "{\"formDisableCtrl\":["
        "{\"bundleName\":\"com.example.duedemo\",\"moduleName\":\"entry\",\"policy\":\"disable\"},"
        "{\"bundleName\":\"com.example.other\",\"moduleName\":\"entry\",\"policy\":\"remove\"}]}";
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry");
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    EXPECT_FALSE(paramControl.IsFormRemove(formRecord));
    
    formRecord.bundleName = "com.example.other";
    EXPECT_FALSE(paramControl.IsFormDisable(formRecord));
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_030 end";
}

/**
 * @tc.name: fmsParamControl_031
 * @tc.desc: test IsFormInfoMatch with dimension match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_031 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "1,2,3", 0, 0, 10);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 2);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 10);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_031 end";
}

/**
 * @tc.name: fmsParamControl_032
 * @tc.desc: test IsFormInfoMatch with version range boundary (start).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_032 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 1);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_032 end";
}

/**
 * @tc.name: fmsParamControl_033
 * @tc.desc: test IsFormInfoMatch with version range boundary (end).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_033 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 10);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_033 end";
}

/**
 * @tc.name: fmsParamControl_034
 * @tc.desc: test IsFormInfoMatch with versionCode out of range.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_034 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 0);
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), Constants::DUE_INVALID_UPDATE_DURATION);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_034 end";
}

/**
 * @tc.name: fmsParamControl_035
 * @tc.desc: test IsFormInfoMatch with lastVersionCode zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_035 start";
    std::string jsonStr = CreateUpdateDurationJson("com.example.duedemo", "entry", "", "", "", 1, 10, 20);
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    formRecord.lastVersionCode = 0;
    EXPECT_EQ(paramControl.GetDueUpdateDuration(formRecord), 20);
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_035 end";
}

/**
 * @tc.name: fmsParamControl_036
 * @tc.desc: test IsFormDisable with version range boundary.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_036 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 1, 10, "disable");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 1);
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    
    formRecord.versionCode = 10;
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_036 end";
}

/**
 * @tc.name: fmsParamControl_037
 * @tc.desc: test IsFormDisable with lastVersionCode zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_037 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 1, 10, "disable");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    formRecord.lastVersionCode = 0;
    EXPECT_TRUE(paramControl.IsFormDisable(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_037 end";
}

/**
 * @tc.name: fmsParamControl_038
 * @tc.desc: test IsFormRemove with dimension match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_038 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "1,2,3", 0, 0, "remove");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 2);
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_038 end";
}

/**
 * @tc.name: fmsParamControl_039
 * @tc.desc: test IsFormRemove with version range boundary.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_039 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 1, 10, "remove");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 1);
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));
    
    formRecord.versionCode = 10;
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_039 end";
}

/**
 * @tc.name: fmsParamControl_040
 * @tc.desc: test IsFormRemove with lastVersionCode zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, fmsParamControl_040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_040 start";
    std::string jsonStr = CreateDisableCtrlJson("com.example.duedemo", "entry", "", "", "", 1, 10, "remove");
    paramControl.DealDueParam(jsonStr);
    FormRecord formRecord = CreateFormRecord("com.example.duedemo", "entry", "", "", 0, 5);
    formRecord.lastVersionCode = 0;
    EXPECT_TRUE(paramControl.IsFormRemove(formRecord));
    GTEST_LOG_(INFO) << "FmsParamControlTest fmsParamControl_040 end";
}
} // namespace AppExecFwk
} // namespace OHOS