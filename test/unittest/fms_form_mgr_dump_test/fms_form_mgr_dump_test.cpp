/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#define private public
#include "common/util/form_dump_mgr.h"
#include "form_mgr/form_mgr_service.h"
#undef private
#include "status_mgr_center/form_status.h"
#include "if_system_ability_manager.h"
#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID_ONE = 1;
class FmsFormMgrDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateProviderData();
};

void FmsFormMgrDumpTest::SetUpTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
}

void FmsFormMgrDumpTest::TearDownTestCase()
{}

void FmsFormMgrDumpTest::SetUp()
{}

void FmsFormMgrDumpTest::TearDown()
{}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: AppendBundleFormInfo Function
 * FunctionPoints: FormMgr AppendBundleFormInfo interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke AppendBundleFormInfo works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_007 start";

    FormRecord formRecord;
    std::string formInfo;
    FormDumpMgr::GetInstance().AppendBundleFormInfo(formRecord, formInfo);
    EXPECT_EQ(false, formInfo.empty());

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_007 end";
}

/**
 * @tc.name: Dump_010
 * @tc.desc: Verify formDumpMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_010 start";
    FormDumpMgr formDumpMgr;
    GTEST_LOG_(INFO) << "Dump_010 end";
}

/**
 * @tc.name: Dump_011
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_011 start";
    FormDBInfo formDBInfo1;
    formDBInfo1.formUserUids = {1, 2, 3};
    formDBInfo1.formId = 1;
    formDBInfo1.formName = "123";
    FormDBInfo formDBInfo2;
    formDBInfo2.formId = 2;
    formDBInfo2.formName = "456";
    formDBInfo2.formUserUids = {4, 5, 6};
    std::vector<FormDBInfo> storageInfos = {formDBInfo1, formDBInfo2};
    std::string formInfos;
    FormDumpMgr::GetInstance().DumpStorageFormInfos(storageInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_011 end";
}

/**
 * @tc.name: Dump_012
 * @tc.desc: Verify DumpTemporaryFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_012 start";
    FormRecord formRecord;
    formRecord.formId = 1;
    formRecord.formUserUids = {1};
    std::vector<FormRecord> formRecordInfos = {formRecord};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_012 end";
}

/**
 * @tc.name: Dump_013
 * @tc.desc: Verify DumpStaticBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_013 start";
    FormInfo formInfo;
    formInfo.bundleName = "bundleName";
    std::vector<FormInfo> bundleFormInfos = {formInfo};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_013 end";
}

/**
 * @tc.name: Dump_014
 * @tc.desc: Verify DumpFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_014 start";
    std::string formInfo = "123";
    FormRecord formRecordInfo;
    formRecordInfo.formId = 123;
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    formRecordInfo.hapSourceDirs = {"1", "2"};
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    formRecordInfo.formUserUids = {1, 2};
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    GTEST_LOG_(INFO) << "Dump_014 end";
}

/**
 * @tc.name: Dump_015
 * @tc.desc: Verify DumpFormSubscribeInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_015 start";
    std::vector<std::string> subscribedKeys = {"1"};
    int64_t count = 1;
    std::string formInfo = "1";
    FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    GTEST_LOG_(INFO) << "Dump_015 end";
}

/**
 * @tc.name: Dump_016
 * @tc.desc: Verify AppendRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_016 start";
    std::string formHostBundleName = "BundleName";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "BundleName";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "BundleName";
    runningFormInfo2.formVisiblity = FormVisibilityType::UNKNOWN;
    runningFormInfo2.formUsageState = FormUsageState::USED;
    RunningFormInfo runningFormInfo3;
    runningFormInfo3.hostBundleName = "BundleName";
    runningFormInfo3.formVisiblity = FormVisibilityType::VISIBLE;
    runningFormInfo3.formUsageState = FormUsageState::UNUSED;
    RunningFormInfo runningFormInfo4;
    runningFormInfo4.hostBundleName = "BundleName";
    runningFormInfo4.formVisiblity = FormVisibilityType::INVISIBLE;
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2,
        runningFormInfo3, runningFormInfo4};
    std::string infosResult = "BundleName";
    FormDumpMgr::GetInstance().AppendRunningFormInfos(formHostBundleName, runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_016 end";
}

/**
 * @tc.name: Dump_017
 * @tc.desc: Verify AppendFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_017 start";
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::OTHER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::DESKTOP, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::SCREEN_LOCK, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::AI_SUGGESTION, infosResult);
    GTEST_LOG_(INFO) << "Dump_017 end";
}

/**
 * @tc.name: Dump_018
 * @tc.desc: Verify DumpRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_018 start";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "1";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "2";
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2};
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_018 end";
}

/**
 * @tc.name: Dump_019
 * @tc.desc: Verify AppendFormStatus
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_019 start";
    std::string formInfo = "formInfo";
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::INIT);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RENDERED);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLED);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RENDERING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLING_DATA);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECOVERING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::DELETING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    GTEST_LOG_(INFO) << "Dump_019 end";
}

/**
 * @tc.name: Dump_020
 * @tc.desc: Verify AppendBundleType
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_020 start";
    std::string formInfo = "formInfo";
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::APP, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::ATOMIC_SERVICE, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::SHARED, formInfo);
    GTEST_LOG_(INFO) << "Dump_020 end";
}

/**
 * @tc.name: Dump_021
 * @tc.desc: Verify formDumpMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_021 start";
    FormDumpMgr formDumpMgr;
    GTEST_LOG_(INFO) << "Dump_021 end";
}

/**
 * @tc.name: Dump_022
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_022 start";
    FormDBInfo formDBInfo1;
    formDBInfo1.formUserUids = {1, 2, 3};
    formDBInfo1.formId = 1;
    formDBInfo1.formName = "123";
    FormDBInfo formDBInfo2;
    formDBInfo2.formId = 2;
    formDBInfo2.formName = "456";
    formDBInfo2.formUserUids = {4, 5, 6};
    std::vector<FormDBInfo> storageInfos = {formDBInfo1, formDBInfo2};
    std::string formInfos;
    FormDumpMgr::GetInstance().DumpStorageFormInfos(storageInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_022 end";
}

/**
 * @tc.name: Dump_023
 * @tc.desc: Verify DumpTemporaryFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_023 start";
    FormRecord formRecord;
    formRecord.formId = 1;
    formRecord.formUserUids = {1};
    std::vector<FormRecord> formRecordInfos = {formRecord};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_023 end";
}

/**
 * @tc.name: Dump_024
 * @tc.desc: Verify DumpStaticBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_024 start";
    FormInfo formInfo;
    formInfo.bundleName = "bundleName";
    std::vector<FormInfo> bundleFormInfos = {formInfo};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_024 end";
}

/**
 * @tc.name: Dump_025
 * @tc.desc: Verify DumpFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_025 start";
    FormRecord formRecordInfo;
    formRecordInfo.formId = 123;
    formRecordInfo.hapSourceDirs = {"1", "2"};
    formRecordInfo.formUserUids = {1, 2};
    std::string formInfo = "123";
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    GTEST_LOG_(INFO) << "Dump_025 end";
}

/**
 * @tc.name: Dump_026
 * @tc.desc: Verify DumpFormSubscribeInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_026 start";
    std::vector<std::string> subscribedKeys = {"1"};
    int64_t count = 1;
    std::string formInfo = "1";
    FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    GTEST_LOG_(INFO) << "Dump_026 end";
}

/**
 * @tc.name: Dump_027
 * @tc.desc: Verify AppendRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_027 start";
    std::string formHostBundleName = "BundleName";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "BundleName";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "BundleName";
    runningFormInfo2.formVisiblity = FormVisibilityType::UNKNOWN;
    runningFormInfo2.formUsageState = FormUsageState::USED;
    RunningFormInfo runningFormInfo3;
    runningFormInfo3.hostBundleName = "BundleName";
    runningFormInfo3.formVisiblity = FormVisibilityType::VISIBLE;
    runningFormInfo3.formUsageState = FormUsageState::UNUSED;
    RunningFormInfo runningFormInfo4;
    runningFormInfo4.hostBundleName = "BundleName";
    runningFormInfo4.formVisiblity = FormVisibilityType::INVISIBLE;
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2,
        runningFormInfo3, runningFormInfo4};
    std::string infosResult = "BundleName";
    FormDumpMgr::GetInstance().AppendRunningFormInfos(formHostBundleName, runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_027 end";
}

/**
 * @tc.name: Dump_028
 * @tc.desc: Verify AppendFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_028 start";
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::OTHER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::DESKTOP, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::SCREEN_LOCK, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::AI_SUGGESTION, infosResult);
    GTEST_LOG_(INFO) << "Dump_028 end";
}

/**
 * @tc.name: Dump_029
 * @tc.desc: Verify DumpRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_029 start";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "1";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "2";
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2};
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_029 end";
}

/**
 * @tc.name: Dump_031
 * @tc.desc: Verify AppendBundleType
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_031 start";
    std::string formInfo = "formInfo";
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::APP, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::ATOMIC_SERVICE, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::SHARED, formInfo);
    GTEST_LOG_(INFO) << "Dump_031 end";
}

/**
 * @tc.name: Dump_010
 * @tc.desc: Verify formDumpMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_010 start";
    FormDumpMgr formDumpMgr;
    GTEST_LOG_(INFO) << "Dump_010 end";
}

/**
 * @tc.name: Dump_011
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_011 start";
    FormDBInfo formDBInfo1;
    formDBInfo1.formUserUids = {1, 2, 3};
    formDBInfo1.formId = 1;
    formDBInfo1.formName = "123";
    FormDBInfo formDBInfo2;
    formDBInfo2.formId = 2;
    formDBInfo2.formName = "456";
    formDBInfo2.formUserUids = {4, 5, 6};
    std::vector<FormDBInfo> storageInfos = {formDBInfo1, formDBInfo2};
    std::string formInfos;
    FormDumpMgr::GetInstance().DumpStorageFormInfos(storageInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_011 end";
}

/**
 * @tc.name: Dump_012
 * @tc.desc: Verify DumpTemporaryFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_012 start";
    FormRecord formRecord;
    formRecord.formId = 1;
    formRecord.formUserUids = {1};
    std::vector<FormRecord> formRecordInfos = {formRecord};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_012 end";
}

/**
 * @tc.name: Dump_013
 * @tc.desc: Verify DumpStaticBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_013 start";
    FormInfo formInfo;
    formInfo.bundleName = "bundleName";
    std::vector<FormInfo> bundleFormInfos = {formInfo};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_013 end";
}

/**
 * @tc.name: Dump_014
 * @tc.desc: Verify DumpFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_014 start";
    std::string formInfo = "123";
    FormRecord formRecordInfo;
    formRecordInfo.formId = 123;
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    formRecordInfo.hapSourceDirs = {"1", "2"};
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    formRecordInfo.formUserUids = {1, 2};
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    GTEST_LOG_(INFO) << "Dump_014 end";
}

/**
 * @tc.name: Dump_015
 * @tc.desc: Verify DumpFormSubscribeInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_015 start";
    std::vector<std::string> subscribedKeys = {"1"};
    int64_t count = 1;
    std::string formInfo = "1";
    FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    GTEST_LOG_(INFO) << "Dump_015 end";
}

/**
 * @tc.name: Dump_016
 * @tc.desc: Verify AppendRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_016 start";
    std::string formHostBundleName = "BundleName";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "BundleName";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "BundleName";
    runningFormInfo2.formVisiblity = FormVisibilityType::UNKNOWN;
    runningFormInfo2.formUsageState = FormUsageState::USED;
    RunningFormInfo runningFormInfo3;
    runningFormInfo3.hostBundleName = "BundleName";
    runningFormInfo3.formVisiblity = FormVisibilityType::VISIBLE;
    runningFormInfo3.formUsageState = FormUsageState::UNUSED;
    RunningFormInfo runningFormInfo4;
    runningFormInfo4.hostBundleName = "BundleName";
    runningFormInfo4.formVisiblity = FormVisibilityType::INVISIBLE;
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2,
        runningFormInfo3, runningFormInfo4};
    std::string infosResult = "BundleName";
    FormDumpMgr::GetInstance().AppendRunningFormInfos(formHostBundleName, runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_016 end";
}

/**
 * @tc.name: Dump_017
 * @tc.desc: Verify AppendFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_017 start";
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::OTHER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::DESKTOP, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::SCREEN_LOCK, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::AI_SUGGESTION, infosResult);
    GTEST_LOG_(INFO) << "Dump_017 end";
}

/**
 * @tc.name: Dump_018
 * @tc.desc: Verify DumpRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_018 start";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "1";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "2";
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2};
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_018 end";
}

/**
 * @tc.name: Dump_019
 * @tc.desc: Verify AppendFormStatus
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_019 start";
    std::string formInfo = "formInfo";
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::INIT);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RENDERED);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLED);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RENDERING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLING_DATA);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECYCLING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::RECOVERING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    FormStatus::GetInstance().SetFormStatus(FORM_ID_ONE, FormFsmStatus::DELETING);
    FormDumpMgr::GetInstance().AppendFormStatus(FORM_ID_ONE, formInfo);
    GTEST_LOG_(INFO) << "Dump_019 end";
}

/**
 * @tc.name: Dump_020
 * @tc.desc: Verify AppendBundleType
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_020 start";
    std::string formInfo = "formInfo";
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::APP, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::ATOMIC_SERVICE, formInfo);
    FormDumpMgr::GetInstance().AppendBundleType(BundleType::SHARED, formInfo);
    GTEST_LOG_(INFO) << "Dump_020 end";
}

/**
 * @tc.name: Dump_021
 * @tc.desc: Verify formDumpMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_021 start";
    FormDumpMgr formDumpMgr;
    GTEST_LOG_(INFO) << "Dump_021 end";
}

/**
 * @tc.name: Dump_022
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_022 start";
    FormDBInfo formDBInfo1;
    formDBInfo1.formUserUids = {1, 2, 3};
    formDBInfo1.formId = 1;
    formDBInfo1.formName = "123";
    FormDBInfo formDBInfo2;
    formDBInfo2.formId = 2;
    formDBInfo2.formName = "456";
    formDBInfo2.formUserUids = {4, 5, 6};
    std::vector<FormDBInfo> storageInfos = {formDBInfo1, formDBInfo2};
    std::string formInfos;
    FormDumpMgr::GetInstance().DumpStorageFormInfos(storageInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_022 end";
}

/**
 * @tc.name: Dump_023
 * @tc.desc: Verify DumpTemporaryFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_023 start";
    FormRecord formRecord;
    formRecord.formId = 1;
    formRecord.formUserUids = {1};
    std::vector<FormRecord> formRecordInfos = {formRecord};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpTemporaryFormInfos(formRecordInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_023 end";
}

/**
 * @tc.name: Dump_024
 * @tc.desc: Verify DumpStaticBundleFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_024 start";
    FormInfo formInfo;
    formInfo.bundleName = "bundleName";
    std::vector<FormInfo> bundleFormInfos = {formInfo};
    std::string formInfos = "123";
    FormDumpMgr::GetInstance().DumpStaticBundleFormInfos(bundleFormInfos, formInfos);
    GTEST_LOG_(INFO) << "Dump_024 end";
}

/**
 * @tc.name: Dump_025
 * @tc.desc: Verify DumpFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_025 start";
    FormRecord formRecordInfo;
    formRecordInfo.formId = 123;
    formRecordInfo.hapSourceDirs = {"1", "2"};
    formRecordInfo.formUserUids = {1, 2};
    std::string formInfo = "123";
    FormDumpMgr::GetInstance().DumpFormInfo(formRecordInfo, formInfo);
    GTEST_LOG_(INFO) << "Dump_025 end";
}

/**
 * @tc.name: Dump_026
 * @tc.desc: Verify DumpFormSubscribeInfo
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_026 start";
    std::vector<std::string> subscribedKeys = {"1"};
    int64_t count = 1;
    std::string formInfo = "1";
    FormDumpMgr::GetInstance().DumpFormSubscribeInfo(subscribedKeys, count, formInfo);
    GTEST_LOG_(INFO) << "Dump_026 end";
}

/**
 * @tc.name: Dump_027
 * @tc.desc: Verify AppendRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_027 start";
    std::string formHostBundleName = "BundleName";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "BundleName";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "BundleName";
    runningFormInfo2.formVisiblity = FormVisibilityType::UNKNOWN;
    runningFormInfo2.formUsageState = FormUsageState::USED;
    RunningFormInfo runningFormInfo3;
    runningFormInfo3.hostBundleName = "BundleName";
    runningFormInfo3.formVisiblity = FormVisibilityType::VISIBLE;
    runningFormInfo3.formUsageState = FormUsageState::UNUSED;
    RunningFormInfo runningFormInfo4;
    runningFormInfo4.hostBundleName = "BundleName";
    runningFormInfo4.formVisiblity = FormVisibilityType::INVISIBLE;
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2,
        runningFormInfo3, runningFormInfo4};
    std::string infosResult = "BundleName";
    FormDumpMgr::GetInstance().AppendRunningFormInfos(formHostBundleName, runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_027 end";
}

/**
 * @tc.name: Dump_028
 * @tc.desc: Verify AppendFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_028 start";
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::OTHER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::DESKTOP, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::SCREEN_LOCK, infosResult);
    FormDumpMgr::GetInstance().AppendFormLocation(Constants::FormLocation::AI_SUGGESTION, infosResult);
    GTEST_LOG_(INFO) << "Dump_028 end";
}

/**
 * @tc.name: Dump_029
 * @tc.desc: Verify DumpRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_1029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_029 start";
    RunningFormInfo runningFormInfo1;
    runningFormInfo1.hostBundleName = "1";
    RunningFormInfo runningFormInfo2;
    runningFormInfo2.hostBundleName = "2";
    std::vector<RunningFormInfo> runningFormInfos = {runningFormInfo1, runningFormInfo2};
    std::string infosResult = "infosResult";
    FormDumpMgr::GetInstance().DumpRunningFormInfos(runningFormInfos, infosResult);
    GTEST_LOG_(INFO) << "Dump_029 end";
}
}
