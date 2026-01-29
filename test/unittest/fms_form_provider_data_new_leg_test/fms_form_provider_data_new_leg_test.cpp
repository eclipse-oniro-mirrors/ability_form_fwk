/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_mgr_errors.h"
#define private public
#include "form_provider_data.h"
#include "form_provider/form_provider_mgr.h"
#include "feature/form_share/form_share_mgr.h"
#undef private
#include "form_ashmem.h"
#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetBundleInfo(bool mockRet);
extern void MockGetAbilityInfoByAction(bool mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockGetFormRecordParams(bool mockRet);
extern void MockIsLimiterEnableRefresh(bool mockRet);
extern void MockConnectServiceAbility(bool mockRet);
extern void MockIsEnableRefresh(bool mockRet);

namespace {
const int32_t AGE = 10;

class FmsFormProviderDataNewLegTest : public testing::Test {
public:
    void SetUp();
    bool InitJsonData();

    nlohmann::json jsonData_;
};
void FmsFormProviderDataNewLegTest::SetUp() {}

bool FmsFormProviderDataNewLegTest::InitJsonData()
{
    nlohmann::json tmpJson;
    tmpJson["name"] = "li";
    tmpJson["age"] = AGE;
    jsonData_["0"] = tmpJson;
    return true;
}

/**
 * @tc.name: FmsFormProviderDataNewLegTest_001
 * @tc.desc: Verify the WriteImageDataToParcel function and WriteToAshmem is false.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FmsFormProviderDataNewLegTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_001 start";
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    Parcel parcel;
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
    EXPECT_EQ(false, formProviderData.WriteImageDataToParcel(parcel, picName, data, 1));
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_001 end";
}

/**
 * @tc.name: FmsFormProviderDataNewLegTest_002
 * @tc.desc: Verify the ConvertRawImageData function and WriteToAshmem is false.
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FmsFormProviderDataNewLegTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_002 start";
    EXPECT_EQ(true, InitJsonData());
    FormProviderData formProviderData(jsonData_);
    std::string picName = "image";
    char* bytes = new char[1];
    bytes[0] = 'a';
    std::shared_ptr<char> data(bytes);
    formProviderData.AddImageData(picName, data, 1);
    EXPECT_EQ(false, formProviderData.ConvertRawImageData());
    GTEST_LOG_(INFO) << "FmsFormProviderDataNewLegTest_002 end";
}

/**
 * @tc.name: FormShareMgr_001
 * @tc.desc: test IsExistFormPackage function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_001 start";
    FormShareMgr formShareMgr;
    std::string bundleName = "aa";
    std::string moduleName = "bb";
    int32_t userId = 100;
    MockGetBundleInfo(false);
    EXPECT_EQ(false, formShareMgr.IsExistFormPackage(bundleName, moduleName, userId));
    GTEST_LOG_(INFO) << "FormShareMgr_001 end";
}

/**
 * @tc.name: FormShareMgr_002
 * @tc.desc: test IsExistFormPackage function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_002 start";
    FormShareMgr formShareMgr;
    std::string bundleName = "aa";
    std::string moduleName = "bb";
    int32_t userId = 100;
    MockGetBundleInfo(true);
    EXPECT_EQ(false, formShareMgr.IsExistFormPackage(bundleName, moduleName, userId));
    GTEST_LOG_(INFO) << "FormShareMgr_002 end";
}

/**
 * @tc.name: FormShareMgr_003
 * @tc.desc: test HandleRecvFormShareInfoFromRemoteTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_003 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    info.bundleName = "aa";
    info.moduleName = "bb";
    info.abilityName = "cc";
    info.formName = "dd";
    info.deviceId = 1;
    int32_t userId = 100;
    MockGetAbilityInfoByAction(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST, formShareMgr.HandleRecvFormShareInfoFromRemoteTask(info,
        userId));
    GTEST_LOG_(INFO) << "FormShareMgr_003 end";
}

/**
 * @tc.name: FormShareMgr_004
 * @tc.desc: test HandleRecvFormShareInfoFromRemoteTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_004 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    info.bundleName = "aa";
    info.moduleName = "bb";
    info.abilityName = "cc";
    info.formName = "dd";
    info.deviceId = 1;
    int32_t userId = 100;
    MockGetAbilityInfoByAction(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_FORM_USER_NOT_EXIST, formShareMgr.HandleRecvFormShareInfoFromRemoteTask(info,
        userId));
    GTEST_LOG_(INFO) << "FormShareMgr_004 end";
}

/**
 * @tc.name: FormShareMgr_005
 * @tc.desc: test CheckFormPackage function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_005 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    std::string formShareInfoKey = "aa";
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formShareMgr.CheckFormPackage(info, formShareInfoKey, userId));
    GTEST_LOG_(INFO) << "FormShareMgr_005 end";
}

/**
 * @tc.name: FormShareMgr_006
 * @tc.desc: test StartFormUser function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_006 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    int32_t userId = 100;
    MockGetAbilityInfoByAction(false);
    formShareMgr.StartFormUser(info, userId);
    GTEST_LOG_(INFO) << "FormShareMgr_006 end";
}

/**
 * @tc.name: FormShareMgr_007
 * @tc.desc: test StartFormUser function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_007 start";
    FormShareMgr formShareMgr;
    FormShareInfo info;
    int32_t userId = 100;
    MockGetAbilityInfoByAction(true);
    formShareMgr.StartFormUser(info, userId);
    GTEST_LOG_(INFO) << "FormShareMgr_007 end";
}

/**
 * @tc.name: FormShareMgr_008
 * @tc.desc: test RemoveFormShareInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_008 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t formId = 1;
    std::string formShareInfoKey = "aa";
    formShareMgr->eventMap_.emplace(formId, formShareInfoKey);
    formShareMgr->RemoveFormShareInfo(formShareInfoKey);
    GTEST_LOG_(INFO) << "FormShareMgr_008 end";
}

/**
 * @tc.name: FormShareMgr_009
 * @tc.desc: test RemoveFormShareInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_009 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t formId = 1;
    std::string formShareInfoKey = "aa";
    std::string stringData = "bb";
    formShareMgr->eventMap_.emplace(formId, stringData);
    formShareMgr->RemoveFormShareInfo(formShareInfoKey);
    GTEST_LOG_(INFO) << "FormShareMgr_009 end";
}

/**
 * @tc.name: FormShareMgr_010
 * @tc.desc: test FinishFreeInstallTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_010 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    formShareMgr->FinishFreeInstallTask(freeInstallOperator);
    GTEST_LOG_(INFO) << "FormShareMgr_010 end";
}

/**
 * @tc.name: FormShareMgr_011
 * @tc.desc: test FinishFreeInstallTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_011 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t formId = 1;
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    formShareMgr->freeInstallOperatorMap_.emplace(formId, freeInstallOperator);
    formShareMgr->FinishFreeInstallTask(freeInstallOperator);
    GTEST_LOG_(INFO) << "FormShareMgr_011 end";
}

/**
 * @tc.name: FormShareMgr_012
 * @tc.desc: test FinishFreeInstallTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_012 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t formId = 1;
    std::string formShareInfoKey = "aa";
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperators =
    std::make_shared<FormFreeInstallOperator>(formShareInfoKey, nullptr);
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    formShareMgr->freeInstallOperatorMap_.emplace(formId, freeInstallOperator);
    formShareMgr->FinishFreeInstallTask(freeInstallOperator);
    GTEST_LOG_(INFO) << "FormShareMgr_012 end";
}

/**
 * @tc.name: FormShareMgr_013
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_013 start";
    FormShareMgr formShareMgr;
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    int32_t resultCode = 2;
    std::string formShareInfoKey = "aa";
    int32_t userId = 100;
    formShareMgr.OnInstallFinished(freeInstallOperator, resultCode, formShareInfoKey, userId);
    GTEST_LOG_(INFO) << "FormShareMgr_013 end";
}

/**
 * @tc.name: FormShareMgr_014
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_014 start";
    FormShareMgr formShareMgr;
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    int32_t resultCode = ERR_OK;
    std::string formShareInfoKey = "aa";
    int32_t userId = 100;
    formShareMgr.OnInstallFinished(freeInstallOperator, resultCode, formShareInfoKey, userId);
    GTEST_LOG_(INFO) << "FormShareMgr_014 end";
}

/**
 * @tc.name: FormShareMgr_015
 * @tc.desc: test OnInstallFinished function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_015 start";
    FormShareMgr formShareMgr;
    std::shared_ptr<FormFreeInstallOperator> freeInstallOperator = nullptr;
    int32_t resultCode = ERR_OK;
    std::string formShareInfoKey = "aa";
    FormShareInfo formShareInfo;
    int32_t userId = 100;
    formShareMgr.shareInfo_.emplace(formShareInfoKey, formShareInfo);
    formShareMgr.OnInstallFinished(freeInstallOperator, resultCode, formShareInfoKey, userId);
    GTEST_LOG_(INFO) << "FormShareMgr_015 end";
}

/**
 * @tc.name: FormShareMgr_016
 * @tc.desc: test HandleFormShareInfoTimeout function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_016 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t eventId = 1;
    formShareMgr->HandleFormShareInfoTimeout(eventId);
    GTEST_LOG_(INFO) << "FormShareMgr_016 end";
}

/**
 * @tc.name: FormShareMgr_017
 * @tc.desc: test HandleFormShareInfoTimeout function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_017 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t eventId = 1;
    std::string stringData = "aa";
    formShareMgr->eventMap_.emplace(eventId, stringData);
    formShareMgr->HandleFormShareInfoTimeout(eventId);
    GTEST_LOG_(INFO) << "FormShareMgr_017 end";
}

/**
 * @tc.name: FormShareMgr_018
 * @tc.desc: test AcquireShareFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_018 start";
    FormShareMgr formShareMgr;
    int64_t formId = 1;
    std::string remoteDeviceId = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formShareMgr.AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormShareMgr_018 end";
}

/**
 * @tc.name: FormShareMgr_019
 * @tc.desc: test HandleProviderShareData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_019 start";
    FormShareMgr formShareMgr;
    int64_t formId = 1;
    std::string remoteDeviceId = "aa";
    AAFwk::WantParams wantParams;
    int64_t requestCode = 2;
    bool result = false;
    MockGetFormRecord(true);
    formShareMgr.HandleProviderShareData(formId, remoteDeviceId, wantParams, requestCode, result);
    GTEST_LOG_(INFO) << "FormShareMgr_019 end";
}

/**
 * @tc.name: FormShareMgr_020
 * @tc.desc: test HandleProviderShareData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_020 start";
    FormShareMgr formShareMgr;
    int64_t formId = 1;
    std::string remoteDeviceId = "aa";
    AAFwk::WantParams wantParams;
    int64_t requestCode = 2;
    bool result = true;
    MockGetFormRecord(true);
    formShareMgr.HandleProviderShareData(formId, remoteDeviceId, wantParams, requestCode, result);
    GTEST_LOG_(INFO) << "FormShareMgr_020 end";
}

/**
 * @tc.name: FormShareMgr_021
 * @tc.desc: test SendResponse function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_021 start";
    FormShareMgr formShareMgr;
    int64_t requestCode = 1;
    int32_t result = 2;
    formShareMgr.SendResponse(requestCode, result);
    GTEST_LOG_(INFO) << "FormShareMgr_021 end";
}

/**
 * @tc.name: FormShareMgr_022
 * @tc.desc: test SendResponse function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_022 start";
    FormShareMgr formShareMgr;
    int64_t requestCode = 1;
    int32_t result = 2;
    std::string stringData = "aa";
    formShareMgr.eventMap_.emplace(requestCode, stringData);
    formShareMgr.SendResponse(requestCode, result);
    GTEST_LOG_(INFO) << "FormShareMgr_022 end";
}

/**
 * @tc.name: FormShareMgr_023
 * @tc.desc: test IsShareForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_023 start";
    FormShareMgr formShareMgr;
    Want want;
    EXPECT_EQ(false, formShareMgr.IsShareForm(want));
    GTEST_LOG_(INFO) << "FormShareMgr_023 end";
}

/**
 * @tc.name: FormShareMgr_024
 * @tc.desc: test OnEventTimeoutResponse function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_024 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t msg = MSG::FORM_SHARE_INFO_DELAY_MSG;
    int64_t eventId = 1;
    formShareMgr->OnEventTimeoutResponse(msg, eventId);
    GTEST_LOG_(INFO) << "FormShareMgr_024 end";
}

/**
 * @tc.name: FormShareMgr_025
 * @tc.desc: test OnEventTimeoutResponse function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_025 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t msg = MSG::FORM_PACKAGE_FREE_INSTALL_DELAY_MSG;
    int64_t eventId = 1;
    formShareMgr->OnEventTimeoutResponse(msg, eventId);
    GTEST_LOG_(INFO) << "FormShareMgr_025 end";
}

/**
 * @tc.name: FormShareMgr_026
 * @tc.desc: test OnEventTimeoutResponse function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormShareMgr_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareMgr_026 start";
    std::shared_ptr<FormShareMgr> formShareMgr = std::make_shared<FormShareMgr>();
    ASSERT_NE(nullptr, formShareMgr);
    int64_t msg = 100;
    int64_t eventId = 1;
    formShareMgr->OnEventTimeoutResponse(msg, eventId);
    GTEST_LOG_(INFO) << "FormShareMgr_026 end";
}

/**
 * @tc.name: FormProviderMgr_001
 * @tc.desc: test ConnectAmsForRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_001 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormRecord record;
    record.needFreeInstall = true;
    Want want;
    record.isCountTimerRefresh = true;
    formProviderMgr.ConnectAmsForRefresh(formId, record, want);
    GTEST_LOG_(INFO) << "FormProviderMgr_001 end";
}

/**
 * @tc.name: FormProviderMgr_002
 * @tc.desc: test ConnectAmsForRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_002 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormRecord record;
    record.needFreeInstall = false;
    Want want;
    MockIsLimiterEnableRefresh(false);
    record.isCountTimerRefresh = true;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL,
        formProviderMgr.ConnectAmsForRefresh(formId, record, want));
    GTEST_LOG_(INFO) << "FormProviderMgr_002 end";
}

/**
 * @tc.name: FormProviderMgr_003
 * @tc.desc: test ConnectAmsForRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_003 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormRecord record;
    record.needFreeInstall = false;
    Want want;
    MockIsLimiterEnableRefresh(true);
    MockConnectServiceAbility(false);
    record.isCountTimerRefresh = true;
    formProviderMgr.ConnectAmsForRefresh(formId, record, want);
    GTEST_LOG_(INFO) << "FormProviderMgr_003 end";
}

/**
 * @tc.name: FormProviderMgr_004
 * @tc.desc: test ConnectAmsForRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_004 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormRecord record;
    record.needFreeInstall = false;
    record.isCountTimerRefresh = true;
    Want want;
    MockIsLimiterEnableRefresh(true);
    MockConnectServiceAbility(true);
    formProviderMgr.ConnectAmsForRefresh(formId, record, want);
    GTEST_LOG_(INFO) << "FormProviderMgr_004 end";
}

/**
 * @tc.name: FormProviderMgr_005
 * @tc.desc: test NotifyProviderFormsBatchDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_005 start";
    FormProviderMgr formProviderMgr;
    std::string bundleName = "";
    std::string abilityName = "";
    std::set<int64_t> formIds;
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formProviderMgr.NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds, userId));
    GTEST_LOG_(INFO) << "FormProviderMgr_005 end";
}

/**
 * @tc.name: FormProviderMgr_006
 * @tc.desc: test NotifyProviderFormsBatchDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_006 start";
    FormProviderMgr formProviderMgr;
    std::string bundleName = "";
    std::string abilityName = "aa";
    std::set<int64_t> formIds;
    int32_t userId = 100;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formProviderMgr.NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds, userId));
    GTEST_LOG_(INFO) << "FormProviderMgr_006 end";
}

/**
 * @tc.name: FormProviderMgr_007
 * @tc.desc: test NotifyProviderFormsBatchDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_007 start";
    FormProviderMgr formProviderMgr;
    std::string bundleName = "bb";
    std::string abilityName = "aa";
    std::set<int64_t> formIds;
    int32_t userId = 100;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formProviderMgr.NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds, userId));
    GTEST_LOG_(INFO) << "FormProviderMgr_007 end";
}

/**
 * @tc.name: FormProviderMgr_008
 * @tc.desc: test UpdateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_008 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormProviderInfo formProviderInfo;
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formProviderMgr.UpdateForm(formId, formProviderInfo));
    GTEST_LOG_(INFO) << "FormProviderMgr_008 end";
}

/**
 * @tc.name: FormProviderMgr_009
 * @tc.desc: test UpdateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_009 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormProviderInfo formProviderInfo;
    MockGetFormRecord(true);
    formProviderMgr.UpdateForm(formId, formProviderInfo);
    GTEST_LOG_(INFO) << "FormProviderMgr_009 end";
}

/**
 * @tc.name: FormProviderMgr_010
 * @tc.desc: test UpdateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_010 start";
    FormProviderMgr formProviderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.versionUpgrade = true;
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_OK, formProviderMgr.UpdateForm(formId, formRecord, formProviderData));
    GTEST_LOG_(INFO) << "FormProviderMgr_010 end";
}

/**
 * @tc.name: FormProviderMgr_011
 * @tc.desc: test IncreaseTimerRefreshCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_011 start";
    std::shared_ptr<FormProviderMgr> formProviderMgr = std::make_shared<FormProviderMgr>();
    ASSERT_NE(nullptr, formProviderMgr);
    int64_t formId = 1;
    MockGetFormRecord(false);
    formProviderMgr->IncreaseTimerRefreshCount(formId);
    GTEST_LOG_(INFO) << "FormProviderMgr_011 end";
}

/**
 * @tc.name: FormProviderMgr_012
 * @tc.desc: test IncreaseTimerRefreshCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_012 start";
    std::shared_ptr<FormProviderMgr> formProviderMgr = std::make_shared<FormProviderMgr>();
    ASSERT_NE(nullptr, formProviderMgr);
    int64_t formId = 1;
    MockGetFormRecord(true);
    formProviderMgr->IncreaseTimerRefreshCount(formId);
    GTEST_LOG_(INFO) << "FormProviderMgr_012 end";
}

/**
 * @tc.name: FormProviderMgr_013
 * @tc.desc: test IsNeedToFresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_013 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    int64_t formId = 1;
    bool isVisibleToFresh = true;
    MockIsEnableRefresh(true);
    EXPECT_EQ(true, formProviderMgr.IsNeedToFresh(record, formId, isVisibleToFresh));
    GTEST_LOG_(INFO) << "FormProviderMgr_013 end";
}

/**
 * @tc.name: FormProviderMgr_014
 * @tc.desc: test IsNeedToFresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_014 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    int64_t formId = 1;
    bool isVisibleToFresh = true;
    MockIsEnableRefresh(false);
    EXPECT_EQ(false, formProviderMgr.IsNeedToFresh(record, formId, isVisibleToFresh));
    GTEST_LOG_(INFO) << "FormProviderMgr_014 end";
}

/**
 * @tc.name: FormProviderMgr_015
 * @tc.desc: test IsNeedToFresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_015 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    int64_t formId = 1;
    bool isVisibleToFresh = false;
    MockIsEnableRefresh(false);
    EXPECT_EQ(false, formProviderMgr.IsNeedToFresh(record, formId, isVisibleToFresh));
    GTEST_LOG_(INFO) << "FormProviderMgr_015 end";
}

/**
 * @tc.name: FormProviderMgr_016
 * @tc.desc: test IsFormCached function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_016 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    record.versionUpgrade = true;
    EXPECT_EQ(false, formProviderMgr.IsFormCached(record));
    GTEST_LOG_(INFO) << "FormProviderMgr_016 end";
}

/**
 * @tc.name: FormProviderMgr_017
 * @tc.desc: test RebindByFreeInstall function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_017 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    Want want;
    sptr<AAFwk::IAbilityConnection> formRefreshConnection = nullptr;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formProviderMgr.RebindByFreeInstall(record, want, formRefreshConnection));
    GTEST_LOG_(INFO) << "FormProviderMgr_017 end";
}

/**
 * @tc.name: FormProviderMgr_018
 * @tc.desc: test RebindByFreeInstall function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_018 start";
    FormProviderMgr formProviderMgr;
    FormRecord record;
    Want want;
    sptr<AAFwk::IAbilityConnection> formRefreshConnection = nullptr;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_OK, formProviderMgr.RebindByFreeInstall(record, want, formRefreshConnection));
    GTEST_LOG_(INFO) << "FormProviderMgr_018 end";
}

/**
 * @tc.name: FormProviderMgr_019
 * @tc.desc: test ConnectAmsForRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_019 start";
    std::shared_ptr<FormProviderMgr> formProviderMgr = std::make_shared<FormProviderMgr>();
    ASSERT_NE(nullptr, formProviderMgr);
    int64_t formId = 1;
    FormRecord record;
    record.needFreeInstall = false;
    record.isCountTimerRefresh = false;
    Want want;
    MockIsLimiterEnableRefresh(true);
    MockConnectServiceAbility(true);
    record.isCountTimerRefresh = false;
    formProviderMgr->ConnectAmsForRefresh(formId, record, want);
    GTEST_LOG_(INFO) << "FormProviderMgr_019 end";
}

/**
 * @tc.name: FormProviderMgr_020
 * @tc.desc: test NotifyProviderFormsBatchDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_020 start";
    FormProviderMgr formProviderMgr;
    std::string bundleName = "bb";
    std::string abilityName = "aa";
    std::set<int64_t> formIds;
    int32_t userId = 100;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_OK, formProviderMgr.NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds, userId));
    GTEST_LOG_(INFO) << "FormProviderMgr_020 end";
}

/**
 * @tc.name: FormProviderMgr_021
 * @tc.desc: test IncreaseTimerRefreshCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_021 start";
    std::shared_ptr<FormProviderMgr> formProviderMgr = std::make_shared<FormProviderMgr>();
    ASSERT_NE(nullptr, formProviderMgr);
    int64_t formId = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    formProviderMgr->IncreaseTimerRefreshCount(formId);
    MockGetFormRecordParams(false);
    GTEST_LOG_(INFO) << "FormProviderMgr_021 end";
}

/**
 * @tc.name: FormProviderMgr_022
 * @tc.desc: test AcquireFormStateBack function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_022 start";
    FormProviderMgr formProviderMgr;
    FormState state = FormState::DEFAULT;
    const std::string provider = "provider";
    const Want wantArg = {};
    EXPECT_EQ(ERR_OK, formProviderMgr.AcquireFormStateBack(state, provider, wantArg));
    GTEST_LOG_(INFO) << "FormProviderMgr_022 end";
}

/**
 * @tc.name: FormProviderMgr_023
 * @tc.desc: test AcquireFormDataBack function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProviderDataNewLegTest, FormProviderMgr_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderMgr_023 start";
    FormProviderMgr formProviderMgr;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    EXPECT_EQ(ERR_OK, formProviderMgr.AcquireFormDataBack(wantParams, requestCode));
    GTEST_LOG_(INFO) << "FormProviderMgr_023 end";
}
}