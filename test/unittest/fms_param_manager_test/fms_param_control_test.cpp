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

#define private public
#include "feature/param_update/param_control.h"
#undef private

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

    ParamCtrl CreateParamCtrl(
        const std::string& bundleName,
        const std::string& moduleName,
        int32_t updateDuration = 10)
    {
        ParamCtrl paramCtrl;
        paramCtrl.bundleName = bundleName;
        paramCtrl.moduleName = moduleName;
        paramCtrl.updateDuration = updateDuration;
        return paramCtrl;
    }

    FormRecord CreateFullFormRecord(
        const std::string& bundleName,
        const std::string& moduleName)
    {
        FormRecord formRecord;
        formRecord.bundleName = bundleName;
        formRecord.moduleName = moduleName;
        formRecord.isEnableUpdate = true;
        formRecord.updateDuration = Constants::TIME_CONVERSION;
        formRecord.formId = 1;
        return formRecord;
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

/**
 * @tc.name: IsSameUpdateDuration_001
 * @tc.desc: test IsSameUpdateDuration with empty compareCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSameUpdateDuration_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_001 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry");
    std::vector<ParamCtrl> compareCtrls;
    bool result = paramControl.IsSameUpdateDuration(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_001 end";
}

/**
 * @tc.name: IsSameUpdateDuration_002
 * @tc.desc: test IsSameUpdateDuration with matching item and same updateDuration.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSameUpdateDuration_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_002 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 10);
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 10);
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSameUpdateDuration(formRecord, paramCtrl, compareCtrls);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_002 end";
}

/**
 * @tc.name: IsSameUpdateDuration_003
 * @tc.desc: test IsSameUpdateDuration with matching item but different updateDuration.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSameUpdateDuration_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_003 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 10);
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 20);
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSameUpdateDuration(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_003 end";
}

/**
 * @tc.name: IsSameUpdateDuration_004
 * @tc.desc: test IsSameUpdateDuration with multiple items, first mismatch but later match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSameUpdateDuration_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_004 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 10);
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl item1 = CreateParamCtrl("com.example.other", "entry", 10);
    ParamCtrl item2 = CreateParamCtrl("com.example.duedemo", "entry", 10);
    compareCtrls.push_back(item1);
    compareCtrls.push_back(item2);
    bool result = paramControl.IsSameUpdateDuration(formRecord, paramCtrl, compareCtrls);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_004 end";
}

/**
 * @tc.name: IsSameUpdateDuration_005
 * @tc.desc: test IsSameUpdateDuration with matching bundleName/moduleName but different updateDuration.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSameUpdateDuration_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_005 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.abilityName = "AbilityA";
    formRecord.formName = "FormA";
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 5);
    paramCtrl.abilityName = "AbilityA";
    paramCtrl.formName = "FormA";
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 10);
    compareItem.abilityName = "AbilityA";
    compareItem.formName = "FormA";
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSameUpdateDuration(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSameUpdateDuration_005 end";
}

/**
 * @tc.name: IsSamePolicy_001
 * @tc.desc: test IsSamePolicy with empty compareCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSamePolicy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_001 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("", "", 0);
    paramCtrl.policy = "disable";
    std::vector<ParamCtrl> compareCtrls;
    bool result = paramControl.IsSamePolicy(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_001 end";
}

/**
 * @tc.name: IsSamePolicy_002
 * @tc.desc: test IsSamePolicy with matching item and same policy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSamePolicy_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_002 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 0);
    paramCtrl.policy = "disable";
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    compareItem.policy = "disable";
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSamePolicy(formRecord, paramCtrl, compareCtrls);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_002 end";
}

/**
 * @tc.name: IsSamePolicy_003
 * @tc.desc: test IsSamePolicy with matching item but different policy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSamePolicy_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_003 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 0);
    paramCtrl.policy = "disable";
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    compareItem.policy = "remove";
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSamePolicy(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_003 end";
}

/**
 * @tc.name: IsSamePolicy_004
 * @tc.desc: test IsSamePolicy with multiple items, first mismatch but later match.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSamePolicy_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_004 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 0);
    paramCtrl.policy = "disable";
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl item1 = CreateParamCtrl("com.example.other", "entry", 0);
    item1.policy = "disable";
    ParamCtrl item2 = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item2.policy = "disable";
    compareCtrls.push_back(item1);
    compareCtrls.push_back(item2);
    bool result = paramControl.IsSamePolicy(formRecord, paramCtrl, compareCtrls);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_004 end";
}

/**
 * @tc.name: IsSamePolicy_005
 * @tc.desc: test IsSamePolicy with matching formInfo but different policy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, IsSamePolicy_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_005 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.abilityName = "AbilityA";
    formRecord.formName = "FormA";
    ParamCtrl paramCtrl = CreateParamCtrl("com.example.duedemo", "entry", 0);
    paramCtrl.abilityName = "AbilityA";
    paramCtrl.formName = "FormA";
    paramCtrl.policy = "remove";
    std::vector<ParamCtrl> compareCtrls;
    ParamCtrl compareItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    compareItem.abilityName = "AbilityA";
    compareItem.formName = "FormA";
    compareItem.policy = "disable";
    compareCtrls.push_back(compareItem);
    bool result = paramControl.IsSamePolicy(formRecord, paramCtrl, compareCtrls);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest IsSamePolicy_005 end";
}

/**
 * @tc.name: ShouldProcessForm_001
 * @tc.desc: test ShouldProcessForm with isEnableUpdate false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_001 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.isEnableUpdate = false;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry");
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_001 end";
}

/**
 * @tc.name: ShouldProcessForm_002
 * @tc.desc: test ShouldProcessForm with updateDuration zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_002 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = 0;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry");
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_002 end";
}

/**
 * @tc.name: ShouldProcessForm_003
 * @tc.desc: test ShouldProcessForm with IsFormInfoMatch fail due to bundleName mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_003 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl item = CreateParamCtrl("com.example.other", "entry");
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_003 end";
}

/**
 * @tc.name: ShouldProcessForm_004
 * @tc.desc: test ShouldProcessForm with IsFormInfoMatch fail due to moduleName mismatch.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_004 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "other");
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_004 end";
}

/**
 * @tc.name: ShouldProcessForm_005
 * @tc.desc: test ShouldProcessForm with abilityName mismatch when paramCtrl has abilityName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_005 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.abilityName = "AbilityA";
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry");
    item.abilityName = "AbilityB";
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_005 end";
}

/**
 * @tc.name: ShouldProcessForm_006
 * @tc.desc: test ShouldProcessForm with formName mismatch when paramCtrl has formName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_006 start";
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.formName = "FormA";
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry");
    item.formName = "FormB";
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_006 end";
}

/**
 * @tc.name: ShouldProcessForm_007
 * @tc.desc: test ShouldProcessForm with isAppUpgrade true and matches both old and new version.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_007 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.versionCode = 5;
    formRecord.lastVersionCode = 5;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    item.appVersionStart = 1;
    item.appVersionEnd = 10;
    paramControl.nextUpdateDurationCtrl_.push_back(item);
    paramControl.preUpdateDurationCtrl_.push_back(item);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, true);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_007 end";
}

/**
 * @tc.name: ShouldProcessForm_008
 * @tc.desc: test ShouldProcessForm with isAppUpgrade false and IsSameUpdateDuration true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_008 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    paramControl.preUpdateDurationCtrl_.push_back(item);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_008 end";
}

/**
 * @tc.name: ShouldProcessForm_009
 * @tc.desc: test ShouldProcessForm with isApply true and item.updateDuration zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_009 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_009 end";
}

/**
 * @tc.name: ShouldProcessForm_010
 * @tc.desc: test ShouldProcessForm with formRecord.updateDuration >= item.updateDuration * TIME_CONVERSION.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_010 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION * 10;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_010 end";
}

/**
 * @tc.name: ShouldProcessForm_011
 * @tc.desc: test ShouldProcessForm with formRecord.updateDuration > item.updateDuration * TIME_CONVERSION.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_011 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION * 15;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_011 end";
}

/**
 * @tc.name: ShouldProcessForm_012
 * @tc.desc: test ShouldProcessForm with all conditions satisfied.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_012 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION * 5;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    bool result = paramControl.ShouldProcessForm(formRecord, item, true, false);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_012 end";
}

/**
 * @tc.name: ShouldProcessForm_013
 * @tc.desc: test ShouldProcessForm with isApply false and not appUpgrade.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_013 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION * 5;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    ParamCtrl nextItem = CreateParamCtrl("com.example.duedemo", "entry", 5);
    paramControl.nextUpdateDurationCtrl_.push_back(nextItem);
    bool result = paramControl.ShouldProcessForm(formRecord, item, false, false);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_013 end";
}

/**
 * @tc.name: ShouldProcessForm_014
 * @tc.desc: test ShouldProcessForm with isApply false and IsSameUpdateDuration matches nextUpdateDurationCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ShouldProcessForm_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_014 start";
    paramControl.DealDueParam("{}");
    FormRecord formRecord = CreateFullFormRecord("com.example.duedemo", "entry");
    formRecord.updateDuration = Constants::TIME_CONVERSION * 5;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    ParamCtrl nextItem = CreateParamCtrl("com.example.duedemo", "entry", 10);
    paramControl.nextUpdateDurationCtrl_.push_back(nextItem);
    bool result = paramControl.ShouldProcessForm(formRecord, item, false, false);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "FmsParamControlTest ShouldProcessForm_014 end";
}

/**
 * @tc.name: ExecUpdateDurationCtrl_001
 * @tc.desc: test ExecUpdateDurationCtrl with empty paramCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecUpdateDurationCtrl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_001 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecUpdateDurationCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_001 end";
}

/**
 * @tc.name: ExecUpdateDurationCtrl_002
 * @tc.desc: test ExecUpdateDurationCtrl with empty paramCtrls and isAppUpgrade true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecUpdateDurationCtrl_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_002 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecUpdateDurationCtrl(true, paramCtrls, true));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_002 end";
}

/**
 * @tc.name: ExecUpdateDurationCtrl_003
 * @tc.desc: test ExecUpdateDurationCtrl with isApply false and empty paramCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecUpdateDurationCtrl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_003 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecUpdateDurationCtrl(false, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_003 end";
}

/**
 * @tc.name: ExecUpdateDurationCtrl_004
 * @tc.desc: test ExecUpdateDurationCtrl with paramCtrls containing one item.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecUpdateDurationCtrl_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_004 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 10);
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecUpdateDurationCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_004 end";
}

/**
 * @tc.name: ExecUpdateDurationCtrl_005
 * @tc.desc: test ExecUpdateDurationCtrl with multiple items in paramCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecUpdateDurationCtrl_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_005 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item1 = CreateParamCtrl("com.example.duedemo", "entry", 10);
    ParamCtrl item2 = CreateParamCtrl("com.example.other", "entry", 20);
    paramCtrls.push_back(item1);
    paramCtrls.push_back(item2);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecUpdateDurationCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecUpdateDurationCtrl_005 end";
}

/**
 * @tc.name: ExecDisableCtrl_001
 * @tc.desc: test ExecDisableCtrl with empty paramCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_001 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_001 end";
}

/**
 * @tc.name: ExecDisableCtrl_002
 * @tc.desc: test ExecDisableCtrl with empty paramCtrls and isAppUpgrade true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_002 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, true));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_002 end";
}

/**
 * @tc.name: ExecDisableCtrl_003
 * @tc.desc: test ExecDisableCtrl with isApply false and empty paramCtrls.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_003 start";
    std::vector<ParamCtrl> paramCtrls;
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(false, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_003 end";
}

/**
 * @tc.name: ExecDisableCtrl_004
 * @tc.desc: test ExecDisableCtrl with paramCtrls containing one disable policy item.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_004 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_004 end";
}

/**
 * @tc.name: ExecDisableCtrl_005
 * @tc.desc: test ExecDisableCtrl with paramCtrls containing one remove policy item.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_005 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "remove";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_005 end";
}

/**
 * @tc.name: ExecDisableCtrl_006
 * @tc.desc: test ExecDisableCtrl with multiple items with different policies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_006 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item1 = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item1.policy = "disable";
    ParamCtrl item2 = CreateParamCtrl("com.example.other", "entry", 0);
    item2.policy = "remove";
    paramCtrls.push_back(item1);
    paramCtrls.push_back(item2);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_006 end";
}

/**
 * @tc.name: ExecDisableCtrl_007
 * @tc.desc: test ExecDisableCtrl with isApply false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_007 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(false, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_007 end";
}

/**
 * @tc.name: ExecDisableCtrl_008
 * @tc.desc: test ExecDisableCtrl with isAppUpgrade true and isApply true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_008 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    item.appVersionStart = 1;
    item.appVersionEnd = 10;
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, true));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_008 end";
}

/**
 * @tc.name: ExecDisableCtrl_009
 * @tc.desc: test ExecDisableCtrl with isAppUpgrade true and isApply false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_009 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    item.appVersionStart = 1;
    item.appVersionEnd = 10;
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(false, paramCtrls, true));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_009 end";
}

/**
 * @tc.name: ExecDisableCtrl_010
 * @tc.desc: test ExecDisableCtrl with IsSamePolicy matching preDisableCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_010 start";
    ParamCtrl preItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    preItem.policy = "disable";
    paramControl.preDisableCtrl_.push_back(preItem);
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    paramControl.preDisableCtrl_.clear();
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_010 end";
}

/**
 * @tc.name: ExecDisableCtrl_011
 * @tc.desc: test ExecDisableCtrl with IsSamePolicy matching nextDisableCtrl when isApply false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_011 start";
    ParamCtrl nextItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    nextItem.policy = "disable";
    paramControl.nextDisableCtrl_.push_back(nextItem);
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(false, paramCtrls, false));
    paramControl.nextDisableCtrl_.clear();
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_011 end";
}

/**
 * @tc.name: ExecDisableCtrl_012
 * @tc.desc: test ExecDisableCtrl with remove policy and IsSamePolicy not matching.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_012 start";
    paramControl.DealDueParam("{}");
    ParamCtrl preItem = CreateParamCtrl("com.example.duedemo", "entry", 0);
    preItem.policy = "remove";
    paramControl.preDisableCtrl_.push_back(preItem);
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "remove";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    paramControl.preDisableCtrl_.clear();
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_012 end";
}

/**
 * @tc.name: ExecDisableCtrl_013
 * @tc.desc: test ExecDisableCtrl with version range matching.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_013 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "disable";
    item.appVersionStart = 1;
    item.appVersionEnd = 10;
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_013 end";
}

/**
 * @tc.name: ExecDisableCtrl_014
 * @tc.desc: test ExecDisableCtrl with different bundleName in paramCtrl.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_014 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item1 = CreateParamCtrl("com.example.bundle1", "module1", 0);
    item1.policy = "disable";
    ParamCtrl item2 = CreateParamCtrl("com.example.bundle2", "module2", 0);
    item2.policy = "remove";
    paramCtrls.push_back(item1);
    paramCtrls.push_back(item2);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_014 end";
}

/**
 * @tc.name: ExecDisableCtrl_015
 * @tc.desc: test ExecDisableCtrl with invalid policy (not disable or remove).
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamControlTest, ExecDisableCtrl_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_015 start";
    paramControl.DealDueParam("{}");
    std::vector<ParamCtrl> paramCtrls;
    ParamCtrl item = CreateParamCtrl("com.example.duedemo", "entry", 0);
    item.policy = "invalid_policy";
    paramCtrls.push_back(item);
    EXPECT_NO_FATAL_FAILURE(paramControl.ExecDisableCtrl(true, paramCtrls, false));
    GTEST_LOG_(INFO) << "FmsParamControlTest ExecDisableCtrl_015 end";
}
} // namespace AppExecFwk
} // namespace OHOS