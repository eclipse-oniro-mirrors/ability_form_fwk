/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_util.h"
#define private public
#include "form_mgr_adapter.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#undef private
#include "mock_ability_manager.h"
#include "mock_bundle_mgr.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using ::testing::_;
using ::testing::Invoke;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockGetBoolParam(bool mockRet);
extern void MockExistTempForm(bool mockRet);
extern void MockGetDBRecord(bool mockRet);
extern void MockGetDBRecordParam(bool mockRet);
extern void MockExistFormRecord(bool mockRet);
extern void MockGetMatchedHostClient(bool mockRet);
extern void MockGetMatchedHostClientParams(bool mockRet);
extern void MockGetMatchedHostClientParamsMatchedId(int64_t mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockGetFormRecordParams(bool mockRet);
extern void MockGetFormRecordParamsUid(bool mockRet);
extern void MockGetFormRecordParamsSysUid(bool mockRet);
extern void MockNotifyProviderFormDelete(bool mockRet);
extern void MockDeleteFormRecord(bool mockRet);
extern void MockDeleteFormInfo(bool mockRet);
extern void MockGetMatchCount(bool mockRet);
extern void MockDeleteData(bool mockRet);
extern void MockRemoveFormTimer(bool mockRet);
extern void MockConnectServiceAbility(bool mockRet);
extern void MockGetIntervalTimer(bool mockRet);
extern void MockGetUpdateAtTimer(bool mockRet);
extern void MockGetDynamicItem(bool mockRet);
extern void MockAllotFormHostRecord(bool mockRet);
extern void MockIsExist(bool mockRet);
extern void MockGetData(bool mockRet);
extern void MockGenerateFormId(bool mockRet);
extern void MockGetCallerBundleName(bool mockRet);
extern void MockGetUidByBundleName(bool mockRet);
extern void MockGetRequestPublishFormInfo(bool mockRet);
extern void MockGetRequestPublishFormInfoWant(OHOS::AAFwk::Want mockWant);
extern void MockGetAbilityInfo(bool mockRet);
extern void MockGetAbilityInfoByAction(bool mockRet);
extern void MockGetFormsInfoByModule(bool mockRet);
extern void MockGetFormsInfoByModuleParam(bool mockRet);
extern void MockGetRefreshCount(bool mockRet);
extern void MockSetNextRefreshTime(bool mockRet);
extern void MockIsRequestPublishForm(bool mockRet);
extern void MockCheckTempEnoughForm(bool mockRet);
extern void MockUpdateDBRecord(bool mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockDeleteHostRecord(bool mockRet);
extern void MockHasFormUserUids(bool mockRet);
extern void MockUpdateFormRecord(bool mockRet);
extern void MockUpdateFormRecordParams(bool mockRet);
extern void MockCheckEnoughForm(bool mockRet);
extern void MockDeleteTempForm(bool mockRet);
extern void MockModifyFormTempFlag(bool mockRet);
extern void MockAddFormUserUid(bool mockRet);
extern void MockGetAllFormInfo(bool mockRet);
extern void MockGetFormHostRecord(bool mockRet);
extern void MockGetFormRecordParamsTemp(bool mockRet);
extern void MockGetAbilityInfoByActionAbilityInfo(bool mockRet);
extern void MockGetAbilityInfoByActionExtensionInfo(bool mockRet);
extern void MockGetRunningFormInfosByFormId(int32_t mockRet);
extern void MockGetRunningFormInfos(int32_t mockRet);

namespace {
class FmsFormMgrAdapterTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FmsFormMgrAdapterTest::SetUp()
{}

void FmsFormMgrAdapterTest::TearDown()
{}

/**
 * @tc.name: FormMgrAdapter_001
 * @tc.desc: test AddForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_001 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_001 end";
}

/**
 * @tc.name: FormMgrAdapter_002
 * @tc.desc: test AddForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_002 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_002 end";
}

/**
 * @tc.name: FormMgrAdapter_003
 * @tc.desc: test AddForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_003 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(false);
    formMgrAdapter.AddForm(formId, want, callerToken, formInfo);
    GTEST_LOG_(INFO) << "FormMgrAdapter_003 end";
}

/**
 * @tc.name: FormMgrAdapter_004
 * @tc.desc: test DeleteForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_004 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_004 end";
}

/**
 * @tc.name: FormMgrAdapter_005
 * @tc.desc: test DeleteForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_005 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistTempForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_005 end";
}

/**
 * @tc.name: FormMgrAdapter_006
 * @tc.desc: test ReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_006 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    sptr<IRemoteObject> callerToken = nullptr;
    bool delCache = true;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_006 end";
}

/**
 * @tc.name: FormMgrAdapter_007
 * @tc.desc: test ReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_007 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool delCache = true;
    MockExistTempForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_007 end";
}

/**
 * @tc.name: FormMgrAdapter_008
 * @tc.desc: test ReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_008 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool delCache = true;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_008 end";
}

/**
 * @tc.name: FormMgrAdapter_009
 * @tc.desc: test HandleReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_009 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_009 end";
}

/**
 * @tc.name: FormMgrAdapter_010
 * @tc.desc: test HandleReleaseForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_010 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_010 end";
}

/**
 * @tc.name: FormMgrAdapter_011
 * @tc.desc: test HandleDeleteTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_011 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_011 end";
}

/**
 * @tc.name: FormMgrAdapter_012
 * @tc.desc: test HandleDeleteFormCache function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_012 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(true);
    MockDeleteFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_012 end";
}

/**
 * @tc.name: FormMgrAdapter_013
 * @tc.desc: test HandleDeleteFormCache function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_013 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(true);
    MockDeleteFormRecord(true);
    MockDeleteFormInfo(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_013 end";
}

/**
 * @tc.name: FormMgrAdapter_014
 * @tc.desc: test HandleDeleteFormCache function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_014 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(true);
    MockDeleteFormRecord(true);
    MockDeleteFormInfo(true);
    MockGetMatchCount(false);
    MockDeleteData(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_014 end";
}

/**
 * @tc.name: FormMgrAdapter_015
 * @tc.desc: test HandleDeleteFormCache function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_015 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(true);
    MockDeleteFormRecord(true);
    MockDeleteFormInfo(true);
    MockGetMatchCount(false);
    MockDeleteData(true);
    MockRemoveFormTimer(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_015 end";
}

/**
 * @tc.name: FormMgrAdapter_016
 * @tc.desc: test UpdateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_016 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    int32_t uid = 1;
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_016 end";
}

/**
 * @tc.name: FormMgrAdapter_017
 * @tc.desc: test UpdateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_017 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    FormProviderData formProviderData;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_017 end";
}

/**
 * @tc.name: FormMgrAdapter_018
 * @tc.desc: test RequestForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_018 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    sptr<IRemoteObject> callerToken = nullptr;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_018 end";
}

/**
 * @tc.name: FormMgrAdapter_019
 * @tc.desc: test RequestForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_019 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    Want want;
    MockExistFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_019 end";
}

/**
 * @tc.name: FormMgrAdapter_020
 * @tc.desc: test NotifyWhetherVisibleForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_020 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t formVisibleType = 2;
    EXPECT_EQ(ERR_OK, formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_020 end";
}

/**
 * @tc.name: FormMgrAdapter_021
 * @tc.desc: test CastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_021 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = -1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_021 end";
}

/**
 * @tc.name: FormMgrAdapter_022
 * @tc.desc: test CastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_022 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(false);
    MockExistTempForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_022 end";
}

/**
 * @tc.name: FormMgrAdapter_023
 * @tc.desc: test CastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_023 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_023 end";
}

/**
 * @tc.name: FormMgrAdapter_024
 * @tc.desc: test CastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_024 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_024 end";
}

/**
 * @tc.name: FormMgrAdapter_025
 * @tc.desc: test HandleCastTempForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_025 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormRecord record;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formMgrAdapter.HandleCastTempForm(formId, record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_025 end";
}

/**
 * @tc.name: FormMgrAdapter_027
 * @tc.desc: test DumpFormInfoByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_027 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string formInfo = "aa";
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormInfoByFormId(formId, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_027 end";
}

/**
 * @tc.name: FormMgrAdapter_028
 * @tc.desc: test DumpFormInfoByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_028 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string formInfo = "aa";
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpFormInfoByFormId(formId, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_028 end";
}

/**
 * @tc.name: FormMgrAdapter_029
 * @tc.desc: test DumpFormTimerByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_029 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string isTimingService = "aa";
    MockGetIntervalTimer(true);
    MockGetUpdateAtTimer(true);
    MockGetDynamicItem(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormTimerByFormId(formId, isTimingService));
    GTEST_LOG_(INFO) << "FormMgrAdapter_029 end";
}

/**
 * @tc.name: FormMgrAdapter_030
 * @tc.desc: test DumpFormTimerByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_030 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string isTimingService = "aa";
    MockGetIntervalTimer(false);
    MockGetUpdateAtTimer(false);
    MockGetDynamicItem(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormTimerByFormId(formId, isTimingService));
    GTEST_LOG_(INFO) << "FormMgrAdapter_030 end";
}

/**
 * @tc.name: FormMgrAdapter_031
 * @tc.desc: test AddExistFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_031 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    FormRecord record;
    int64_t formId = 1;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_031 end";
}

/**
 * @tc.name: FormMgrAdapter_032
 * @tc.desc: test AddExistFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_032 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    FormRecord record;
    record.needRefresh = true;
    int64_t formId = 1;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(true);
    MockIsExist(false);
    formMgrAdapter.AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo);
    GTEST_LOG_(INFO) << "FormMgrAdapter_032 end";
}

/**
 * @tc.name: FormMgrAdapter_033
 * @tc.desc: test AddExistFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_033 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    FormRecord record;
    record.needRefresh = false;
    int64_t formId = 1;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(true);
    MockIsExist(true);
    formMgrAdapter.AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo);
    GTEST_LOG_(INFO) << "FormMgrAdapter_033 end";
}

/**
 * @tc.name: FormMgrAdapter_034
 * @tc.desc: test AddExistFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_034 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    FormRecord record;
    record.needRefresh = false;
    record.formTempFlag = true;
    int64_t formId = 1;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(true);
    MockIsExist(true);
    MockGetData(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.AddExistFormRecord(info, callerToken, record, formId, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_034 end";
}

/**
 * @tc.name: FormMgrAdapter_035
 * @tc.desc: test AllotFormByInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_035 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGenerateFormId(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.AllotFormByInfo(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_035 end";
}

/**
 * @tc.name: FormMgrAdapter_036
 * @tc.desc: test AddNewFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_036 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AddNewFormRecord(info, formId, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_036 end";
}

/**
 * @tc.name: FormMgrAdapter_037
 * @tc.desc: test AddNewFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_037 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(true);
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formMgrAdapter.AddNewFormRecord(info, formId, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_037 end";
}

/**
 * @tc.name: FormMgrAdapter_038
 * @tc.desc: test AddFormTimer function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_038 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    formRecord.isEnableUpdate = false;
    formRecord.formTempFlag = true;
    EXPECT_EQ(ERR_OK, formMgrAdapter.AddFormTimer(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_038 end";
}

/**
 * @tc.name: FormMgrAdapter_039
 * @tc.desc: test AddFormTimer function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_039 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    formRecord.isEnableUpdate = true;
    formRecord.formTempFlag = false;
    formRecord.updateDuration = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.AddFormTimer(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_039 end";
}

/**
 * @tc.name: FormMgrAdapter_040
 * @tc.desc: test AddFormTimer function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_040 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    formRecord.isEnableUpdate = true;
    formRecord.formTempFlag = false;
    formRecord.updateDuration = -1;
    formRecord.updateAtHour = 0;
    formRecord.updateAtMin = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.AddFormTimer(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_040 end";
}

/**
 * @tc.name: FormMgrAdapter_041
 * @tc.desc: test AddFormTimer function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_041 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    formRecord.isEnableUpdate = true;
    formRecord.formTempFlag = false;
    formRecord.updateDuration = -1;
    formRecord.updateAtHour = -1;
    formRecord.updateAtMin = -1;
    EXPECT_EQ(ERR_OK, formMgrAdapter.AddFormTimer(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_041 end";
}

/**
 * @tc.name: FormMgrAdapter_042
 * @tc.desc: test HandleEventNotify function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_042 start";
    FormMgrAdapter formMgrAdapter;
    std::string providerKey = "aa";
    std::vector<int64_t> formIdsByProvider;
    int32_t formVisibleType = 1;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formMgrAdapter.HandleEventNotify(providerKey, formIdsByProvider, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_042 end";
}

/**
 * @tc.name: FormMgrAdapter_043
 * @tc.desc: test HandleEventNotify function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_043 start";
    FormMgrAdapter formMgrAdapter;
    std::string providerKey = "aa";
    std::vector<int64_t> formIdsByProvider;
    int32_t formVisibleType = 1;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleEventNotify(providerKey, formIdsByProvider, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_043 end";
}

/**
 * @tc.name: FormMgrAdapter_044
 * @tc.desc: test AcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_044 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    FormItemInfo info;
    WantParams wantParams;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams));
    GTEST_LOG_(INFO) << "FormMgrAdapter_044 end";
}

/**
 * @tc.name: FormMgrAdapter_045
 * @tc.desc: test AcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_045 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams));
    GTEST_LOG_(INFO) << "FormMgrAdapter_045 end";
}

/**
 * @tc.name: FormMgrAdapter_046
 * @tc.desc: test GetFormItemInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_046 start";
    FormMgrAdapter formMgrAdapter;
    AAFwk::Want want;
    BundleInfo bundleInfo;
    FormInfo formInfo;
    FormItemInfo formItemInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION,
        formMgrAdapter.GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_046 end";
}

/**
 * @tc.name: FormMgrAdapter_047
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_047 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    int64_t nextTime = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_047 end";
}

/**
 * @tc.name: FormMgrAdapter_048
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_048 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_048 end";
}

/**
 * @tc.name: FormMgrAdapter_050
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_050 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetUidByBundleName(false);
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_050 end";
}

/**
 * @tc.name: FormMgrAdapter_051
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_051 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetUidByBundleName(false);
    MockGetFormRecord(true);
    formMgrAdapter.SetNextRefreshTime(formId, nextTime);
    GTEST_LOG_(INFO) << "FormMgrAdapter_051 end";
}

/**
 * @tc.name: FormMgrAdapter_052
 * @tc.desc: test AddRequestPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_052 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo formItemInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    MockGetRequestPublishFormInfo(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
        formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_052 end";
}

/**
 * @tc.name: FormMgrAdapter_053
 * @tc.desc: test AddRequestPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_053, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_053 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo formItemInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    MockGetRequestPublishFormInfo(false);
    formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo);
    GTEST_LOG_(INFO) << "FormMgrAdapter_053 end";
}

/**
 * @tc.name: FormMgrAdapter_054
 * @tc.desc: test IsRequestPublishFormSupported function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_054, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_054 start";
    FormMgrAdapter formMgrAdapter;
    MockGetAbilityInfoByAction(true);
    EXPECT_EQ(false, formMgrAdapter.IsRequestPublishFormSupported());
    GTEST_LOG_(INFO) << "FormMgrAdapter_054 end";
}

/**
 * @tc.name: FormMgrAdapter_055
 * @tc.desc: test IsRequestPublishFormSupported function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_055, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_055 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    FormMgrAdapter formMgrAdapter;
    MockGetAbilityInfo(false);
    MockGetAbilityInfoByAction(true);
    EXPECT_CALL(*bmsProxy, CheckIsSystemAppByUid(_)).Times(1).WillRepeatedly(Return(true));
    std::string bundleName = "com.ohos.launcher";
    EXPECT_CALL(*bmsProxy, GetNameForUid(_, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<1>(bundleName), Return(true)));
    EXPECT_EQ(false, formMgrAdapter.IsRequestPublishFormSupported());
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_055 end";
}

/**
 * @tc.name: FormMgrAdapter_056
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_056, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_056 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string abilityName = "";
    Want want;
    std::string provider = "";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_056 end";
}

/**
 * @tc.name: FormMgrAdapter_057
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_057, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_057 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string abilityName = "aa";
    Want want;
    std::string provider = "";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string());
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string());
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_057 end";
}

/**
 * @tc.name: FormMgrAdapter_059
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_059 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string abilityName = "aa";
    Want want;
    std::string provider = "";
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    MockGetFormsInfoByModule(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_059 end";
}

/**
 * @tc.name: FormMgrAdapter_060
 * @tc.desc: test AcquireFormState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_060 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireFormState(want, callerToken, stateInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_060 end";
}

/**
 * @tc.name: FormMgrAdapter_061
 * @tc.desc: test AcquireFormState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_061, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_061 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormStateInfo stateInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireFormState(want, callerToken, stateInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_061 end";
}

/**
 * @tc.name: FormMgrAdapter_062
 * @tc.desc: test SetNextRefreshTimeLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_062, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_062 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    int32_t userId = 2;
    MockGetRefreshCount(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_REFRESH, formMgrAdapter.SetNextRefreshTimeLocked(formId, nextTime, userId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_062 end";
}

/**
 * @tc.name: FormMgrAdapter_063
 * @tc.desc: test SetNextRefreshTimeLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_063, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_063 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    int32_t userId = 2;
    MockGetRefreshCount(false);
    MockSetNextRefreshTime(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.SetNextRefreshTimeLocked(formId, nextTime, userId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_063 end";
}

/**
 * @tc.name: FormMgrAdapter_064
 * @tc.desc: test SetNextRefreshTimeLocked function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_064, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_064 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    int32_t userId = 2;
    MockGetRefreshCount(false);
    MockSetNextRefreshTime(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.SetNextRefreshTimeLocked(formId, nextTime, userId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_064 end";
}

/**
 * @tc.name: FormMgrAdapter_065
 * @tc.desc: test IsUpdateValid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_065, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_065 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::string bundleName = "";
    EXPECT_EQ(false, formMgrAdapter.IsUpdateValid(formId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_065 end";
}

/**
 * @tc.name: FormMgrAdapter_066
 * @tc.desc: test IsUpdateValid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_066, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_066 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::string bundleName = "aa";
    EXPECT_EQ(true, formMgrAdapter.IsUpdateValid(formId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_066 end";
}

/**
 * @tc.name: FormMgrAdapter_067
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_067, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_067 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RouterEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_067 end";
}

/**
 * @tc.name: FormMgrAdapter_068
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_068, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_068 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.RouterEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_068 end";
}

/**
 * @tc.name: FormMgrAdapter_069
 * @tc.desc: test IsFormCached function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_069, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_069 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord record;
    record.versionUpgrade = true;
    EXPECT_EQ(false, formMgrAdapter.IsFormCached(record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_069 end";
}

/**
 * @tc.name: FormMgrAdapter_070
 * @tc.desc: test IsFormCached function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_070, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_070 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord record;
    record.versionUpgrade = false;
    EXPECT_EQ(true, formMgrAdapter.IsFormCached(record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_070 end";
}

/**
 * @tc.name: FormMgrAdapter_071
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_071, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_071 start";
    FormMgrAdapter formMgrAdapter;
    int64_t matchedFormId = 1;
    FormRecord formRecord;
    formRecord.formVisibleNotify = false;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    EXPECT_EQ(false, formMgrAdapter.CreateHandleEventMap(matchedFormId, formRecord, eventMaps));
    GTEST_LOG_(INFO) << "FormMgrAdapter_071 end";
}

/**
 * @tc.name: FormMgrAdapter_072
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_072, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_072 start";
    FormMgrAdapter formMgrAdapter;
    int64_t matchedFormId = 1;
    FormRecord formRecord;
    formRecord.formVisibleNotify = true;
    formRecord.bundleName = "aa";
    formRecord.abilityName = "bb";
    std::map<std::string, std::vector<int64_t>> eventMaps;
    std::string providerKey = formRecord.bundleName + Constants::NAME_DELIMITER + formRecord.abilityName;
    std::vector<int64_t> matchedFormIds;
    matchedFormIds.emplace_back(matchedFormId);
    eventMaps.emplace(providerKey, matchedFormIds);
    EXPECT_EQ(true, formMgrAdapter.CreateHandleEventMap(matchedFormId, formRecord, eventMaps));
    GTEST_LOG_(INFO) << "FormMgrAdapter_072 end";
}

/**
 * @tc.name: FormMgrAdapter_073
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_073, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_073 start";
    FormMgrAdapter formMgrAdapter;
    int64_t matchedFormId = 1;
    FormRecord formRecord;
    formRecord.formVisibleNotify = true;
    formRecord.bundleName = "aa";
    formRecord.abilityName = "bb";
    std::map<std::string, std::vector<int64_t>> eventMaps;
    EXPECT_EQ(true, formMgrAdapter.CreateHandleEventMap(matchedFormId, formRecord, eventMaps));
    GTEST_LOG_(INFO) << "FormMgrAdapter_073 end";
}

/**
 * @tc.name: FormMgrAdapter_074
 * @tc.desc: test DeleteInvalidForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_074, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_074 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrAdapter_074 end";
}

/**
 * @tc.name: FormMgrAdapter_075
 * @tc.desc: test DeleteInvalidForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_075, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_075 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(ERR_OK, formMgrAdapter.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrAdapter_075 end";
}

/**
 * @tc.name: FormMgrAdapter_026
 * @tc.desc: test DeleteForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_026 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistTempForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_026 end";
}
/**
 * @tc.name: FormMgrAdapter_076
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_076, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_076 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(true);
    MockCheckTempEnoughForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_076 end";
}

/**
 * @tc.name: FormMgrAdapter_077
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_077, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_077 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(false);
    MockCheckTempEnoughForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_077 end";
}

/**
 * @tc.name: FormMgrAdapter_078
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_078, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_078 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_078 end";
}

/**
 * @tc.name: FormMgrAdapter_079
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_079, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_079 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_079 end";
}

/**
 * @tc.name: FormMgrAdapter_080
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_080, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_080 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(true);
    MockDeleteFormRecord(true);
    MockDeleteFormInfo(true);
    MockGetMatchCount(true);
    MockDeleteData(true);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_080 end";
}

/**
 * @tc.name: FormMgrAdapter_081
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_081, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_081 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    int32_t uid = 1;
    int64_t formId = 2;
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_081 end";
}

/**
 * @tc.name: FormMgrAdapter_082
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_082, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_082 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    int32_t uid = 1;
    int64_t formId = 2;
    MockUpdateDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_082 end";
}

/**
 * @tc.name: FormMgrAdapter_083
 * @tc.desc: test UpdateForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_083, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_083 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    FormProviderData formProviderData;
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_083 end";
}

/**
 * @tc.name: FormMgrAdapter_084
 * @tc.desc: test RequestForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_084, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_084 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    Want want;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_084 end";
}

/**
 * @tc.name: FormMgrAdapter_085
 * @tc.desc: test RequestForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_085, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_085 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    Want want;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_085 end";
}

/**
 * @tc.name: FormMgrAdapter_086
 * @tc.desc: test NotifyWhetherVisibleForms function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_086, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_086 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t formVisibleType = 2;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_086 end";
}

/**
 * @tc.name: FormMgrAdapter_087
 * @tc.desc: test NotifyWhetherVisibleForms function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_087, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_087 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t formVisibleType = 2;
    EXPECT_EQ(ERR_OK, formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_087 end";
}

/**
 * @tc.name: FormMgrAdapter_088
 * @tc.desc: test isFormShouldUpdateProviderInfoToHost function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_088, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_088 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    int64_t matchedFormId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t userId = FormUtil::GetCurrentAccountId();
    EXPECT_EQ(false, formMgrAdapter.isFormShouldUpdateProviderInfoToHost(matchedFormId, userId,
        callerToken, formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_088 end";
}

/**
 * @tc.name: FormMgrAdapter_089
 * @tc.desc: test isFormShouldUpdateProviderInfoToHost function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_089, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_089 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    int64_t matchedFormId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t userId = FormUtil::GetCurrentAccountId();
    MockGetFormRecord(true);
    EXPECT_EQ(false, formMgrAdapter.isFormShouldUpdateProviderInfoToHost(matchedFormId, userId,
        callerToken, formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_089 end";
}

/**
 * @tc.name: FormMgrAdapter_090
 * @tc.desc: test CheckIsSystemAppByBundleName function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_090, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_090 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    std::string bundleName = "aa";
    int32_t userId = FormUtil::GetCurrentAccountId();
    EXPECT_EQ(false, formMgrAdapter.CheckIsSystemAppByBundleName(iBundleMgr, userId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_090 end";
}

/**
 * @tc.name: FormMgrAdapter_091
 * @tc.desc: test HandleCastTempForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_091, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_091 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormRecord record;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleCastTempForm(formId, record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_091 end";
}

/**
 * @tc.name: FormMgrAdapter_092
 * @tc.desc: test DumpStorageFormInfos function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_092, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_092 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos = "";
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpStorageFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_092 end";
}

/**
 * @tc.name: FormMgrAdapter_093
 * @tc.desc: test DumpStorageFormInfos function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_093, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_093 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpStorageFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_093 end";
}

/**
 * @tc.name: FormMgrAdapter_094
 * @tc.desc: test DumpFormInfoByBundleName function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_094, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_094 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string formInfos ;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpFormInfoByBundleName(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_094 end";
}

/**
 * @tc.name: FormMgrAdapter_095
 * @tc.desc: test DumpFormInfoByBundleName function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_095, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_095 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string formInfos = "";
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormInfoByBundleName(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_095 end";
}

/**
 * @tc.name: FormMgrAdapter_097
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_097, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_097 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_097 end";
}

/**
 * @tc.name: FormMgrAdapter_098
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_098, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_098 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(false);
    MockGetDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_098 end";
}

/**
 * @tc.name: FormMgrAdapter_099
 * @tc.desc: test AllotFormByInfo function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_099, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_099 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGenerateFormId(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AllotFormByInfo(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_099 end";
}

/**
 * @tc.name: FormMgrAdapter_0100
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0100 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    MockGetBoolParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0100 end";
}

/**
 * @tc.name: FormMgrAdapter_0101
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0101, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0101 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("abilityName");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetElement(elementName);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "name";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0101 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0101 end";
}

/**
 * @tc.name: FormMgrAdapter_0102
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0102, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0102 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("abilityName");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "name";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0102 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0102 end";
}

/**
 * @tc.name: FormMgrAdapter_0103
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("abilityName");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103 end";
}

/**
 * @tc.name: FormMgrAdapter_0104
 * @tc.desc: test DeleteForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0104, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0104 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0104 end";
}

/**
 * @tc.name: FormMgrAdapter_0105
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0105, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0105 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = true;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0105 end";
}

/**
 * @tc.name: FormMgrAdapter_0106
 * @tc.desc: test ReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0106, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0106 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = false;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0106 end";
}

/**
 * @tc.name: FormMgrAdapter_0107
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0107, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0107 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = false;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0107 end";
}

/**
 * @tc.name: FormMgrAdapter_0108
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0108, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0108 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = false;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(false);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0108 end";
}

/**
 * @tc.name: FormMgrAdapter_0109
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0109, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0109 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0109 end";
}

/**
 * @tc.name: FormMgrAdapter_0110
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0110, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0110 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(false);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0110 end";
}

/**
 * @tc.name: FormMgrAdapter_0111
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0111, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0111 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(false);
    MockRemoveFormTimer(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0111 end";
}

/**
 * @tc.name: FormMgrAdapter_0112
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0112, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0112 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(false);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0112 end";
}

/**
 * @tc.name: FormMgrAdapter_0113
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0113, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0113 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    MockUpdateDBRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0113 end";
}

/**
 * @tc.name: FormMgrAdapter_0114
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0114, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0114 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0114 end";
}

/**
 * @tc.name: FormMgrAdapter_0115
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0115, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0115 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(true);
    MockDeleteHostRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0115 end";
}

/**
 * @tc.name: FormMgrAdapter_0116
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0116, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0116 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(false);
    MockNotifyProviderFormDelete(true);
    MockDeleteHostRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0116 end";
}

/**
 * @tc.name: FormMgrAdapter_0117
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0117, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0117 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0117 end";
}

/**
 * @tc.name: FormMgrAdapter_0118
 * @tc.desc: test UpdateForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0118, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0118 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0118 end";
}

/**
 * @tc.name: FormMgrAdapter_0119
 * @tc.desc: test UpdateForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0119, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0119 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 0;
    FormProviderData formProviderData;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0119 end";
}

/**
 * @tc.name: FormMgrAdapter_0120
 * @tc.desc: test RequestForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0120, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0120 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0120 end";
}

/**
 * @tc.name: FormMgrAdapter_0121
 * @tc.desc: test RequestForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0121, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0121 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    Want want;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    EXPECT_EQ(ERR_OK, formMgrAdapter.RequestForm(formId, callerToken, want));
    MockGetMatchedHostClientParamsMatchedId(0);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0121 end";
}

/**
 * @tc.name: FormMgrAdapter_0122
 * @tc.desc: test FormMgrAdapter_0122 function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0122, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0122 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    FormMgrAdapter formMgrAdapter;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    int64_t formId3 = 3;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId1);
    formIds.emplace_back(formId2);
    formIds.emplace_back(formId3);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t formVisibleType = 2;
    MockGetFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId2);
    MockUpdateFormRecord(true);
    MockUpdateFormRecordParams(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    MockGetMatchedHostClientParamsMatchedId(0);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0122 end";
}

/**
 * @tc.name: FormMgrAdapter_0123
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0123, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0123 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0123 end";
}

/**
 * @tc.name: FormMgrAdapter_0124
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0124, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0124 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0124 end";
}

/**
 * @tc.name: FormMgrAdapter_0125
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0125, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0125 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0125 end";
}

/**
 * @tc.name: FormMgrAdapter_0126
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0126, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0126 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0126 end";
}

/**
 * @tc.name: FormMgrAdapter_0127
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0127, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0127 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0127 end";
}

/**
 * @tc.name: FormMgrAdapter_0128
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0128, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0128 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    MockDeleteTempForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0128 end";
}

/**
 * @tc.name: FormMgrAdapter_0129
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0129, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0129 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    MockDeleteTempForm(true);
    MockModifyFormTempFlag(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0129 end";
}

/**
 * @tc.name: FormMgrAdapter_0130
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0130, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0130 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    MockDeleteTempForm(true);
    MockModifyFormTempFlag(true);
    MockAddFormUserUid(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0130 end";
}

/**
 * @tc.name: FormMgrAdapter_0131
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0131, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0131 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    MockDeleteTempForm(true);
    MockModifyFormTempFlag(true);
    MockAddFormUserUid(true);
    MockUpdateDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0131 end";
}

/**
 * @tc.name: FormMgrAdapter_0132
 * @tc.desc: test CastTempForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0132, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0132 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistFormRecord(true);
    MockExistTempForm(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(formId);
    MockCheckEnoughForm(true);
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    MockDeleteTempForm(true);
    MockModifyFormTempFlag(true);
    MockAddFormUserUid(true);
    MockUpdateDBRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.CastTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0132 end";
}

/**
 * @tc.name: FormMgrAdapter_0133
 * @tc.desc: test DumpStorageFormInfos function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0133, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0133 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    MockGetAllFormInfo(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpStorageFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0133 end";
}

/**
 * @tc.name: FormMgrAdapter_0134
 * @tc.desc: test DumpFormInfoByFormId function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0134, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0134 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string formInfo = "aa";
    MockGetFormRecord(true);
    MockGetFormHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormInfoByFormId(formId, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0134 end";
}

/**
 * @tc.name: FormMgrAdapter_0135
 * @tc.desc: test DumpFormTimerByFormId function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0135, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0135 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string isTimingService = "aa";
    MockGetIntervalTimer(false);
    MockGetUpdateAtTimer(false);
    MockGetDynamicItem(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormTimerByFormId(formId, isTimingService));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0135 end";
}

/**
 * @tc.name: FormMgrAdapter_0136
 * @tc.desc: test DumpFormTimerByFormId function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0136, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0136 start";
    FormMgrAdapter formMgrAdapter;
    std::int64_t formId = 1;
    std::string isTimingService = "aa";
    MockGetIntervalTimer(false);
    MockGetUpdateAtTimer(true);
    MockGetDynamicItem(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormTimerByFormId(formId, isTimingService));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0136 end";
}

/**
 * @tc.name: FormMgrAdapter_0137
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0137, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0137 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = true;
    MockExistTempForm(false);
    MockGetDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0137 end";
}

/**
 * @tc.name: FormMgrAdapter_0138
 * @tc.desc: test UpdateForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0138, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0138 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 0;
    FormProviderData formProviderData;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0138 end";
}

/**
 * @tc.name: FormMgrAdapter_0139
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0139, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0139 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0139 end";
}

/**
 * @tc.name: FormMgrAdapter_0140
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0140, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0140 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsTemp(false);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID, formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0140 end";
}

/**
 * @tc.name: FormMgrAdapter_0141
 * @tc.desc: test AddNewFormRecord function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0141, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0141 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    info.SetProviderBundleName("bundle");
    info.SetHostBundleName("host");
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockAllotFormHostRecord(true);
    MockConnectServiceAbility(false);
    MockUpdateDBRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.AddNewFormRecord(info, formId, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0141 end";
}

/**
 * @tc.name: FormMgrAdapter_0142
 * @tc.desc: test AddFormTimer function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0142, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0142 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    formRecord.isEnableUpdate = true;
    formRecord.formTempFlag = true;
    EXPECT_EQ(ERR_OK, formMgrAdapter.AddFormTimer(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0142 end";
}

/**
 * @tc.name: FormMgrAdapter_0143
 * @tc.desc: test GetBundleInfo function and the return value is ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0143, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0143 start";
    FormMgrAdapter formMgrAdapter;
    std::string str = "aa";
    Want want = {};
    want.SetElementName("bundleName", "abilityName");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    BundleInfo bundleInfo = {};
    std::string packageName = "";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "FormMgrAdapter_0143 bmsTask called";
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_EQ(formMgrAdapter.GetBundleInfo(want, bundleInfo, packageName), ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0143 end";
}

/**
 * @tc.name: FormMgrAdapter_0144
 * @tc.desc: test GetBundleInfo function and the return value is ERR_APPEXECFWK_FORM_NO_SUCH_MODULE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0144, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0144 start";
    FormMgrAdapter formMgrAdapter;
    std::string str = "aa";
    Want want = {};
    want.SetElementName("bundleName", "abilityName");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    BundleInfo bundleInfo = {};
    std::string packageName = "";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "moduleName";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "name";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0144 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_EQ(formMgrAdapter.GetBundleInfo(want, bundleInfo, packageName), ERR_APPEXECFWK_FORM_NO_SUCH_MODULE);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0144 end";
}

/**
 * @tc.name: FormMgrAdapter_0145
 * @tc.desc: test GetFormInfo function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0145, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0145 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("", "abilityName");
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.GetFormInfo(want, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0145 end";
}

/**
 * @tc.name: FormMgrAdapter_0146
 * @tc.desc: test GetFormInfo function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0146, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0146 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("bundleName", "");
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.GetFormInfo(want, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0146 end";
}

/**
 * @tc.name: FormMgrAdapter_0147
 * @tc.desc: test GetFormInfo function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0147, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0147 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("bundleName", "abilityName");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string());
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string());
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.GetFormInfo(want, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0147 end";
}

/**
 * @tc.name: FormMgrAdapter_0148
 * @tc.desc: test GetFormInfo function and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0148, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("bundleName", "abilityName");
    MockGetFormsInfoByModule(true);
    MockGetFormsInfoByModuleParam(false);
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE, formMgrAdapter.GetFormInfo(want, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 end";
}

/**
 * @tc.name: FormMgrAdapter_0149
 * @tc.desc: test GetFormItemInfo function and the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0149, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0149 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int32_t dimensionId = 2;
    AAFwk::Want want;
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    BundleInfo bundleInfo;
    FormInfo formInfo;
    formInfo.supportDimensions.push_back(dimensionId);
    formInfo.defaultDimension = dimensionId;
    FormItemInfo formItemInfo;
    MockGetCallerBundleName(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED, formMgrAdapter.GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0149 end";
}

/**
 * @tc.name: FormMgrAdapter_0150
 * @tc.desc: test IsDimensionValid function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0150, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0150 start";
    FormMgrAdapter formMgrAdapter;
    FormInfo formInfo;
    formInfo.supportDimensions.push_back(1);
    int32_t dimensionId = -1;
    MockGetCallerBundleName(true);
    EXPECT_FALSE(formMgrAdapter.IsDimensionValid(formInfo, dimensionId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0150 end";
}

/**
 * @tc.name: FormMgrAdapter_0151
 * @tc.desc: test GetFormInfo function and the return value is ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0151, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0151 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("bundleName", "abilityName");
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(false);
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY, formMgrAdapter.GetFormInfo(want, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0151 end";
}

/**
 * @tc.name: FormMgrAdapter_0152
 * @tc.desc: test CreateFormItemInfo function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0152, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0152 start";
    FormMgrAdapter formMgrAdapter;
    ModuleInfo moduleInfo1 = {};
    moduleInfo1.moduleName = "moduleName1";
    ModuleInfo moduleInfo2 = {};
    moduleInfo2.moduleName = "moduleName2";
    AbilityInfo info1 = {};
    info1.name = "abilityName1";
    info1.isModuleJson = false;
    info1.hapPath = std::string(Constants::ABS_CODE_PATH) + "/res";
    AbilityInfo info2 = {};
    info2.name = "abilityName1";
    info2.isModuleJson = true;
    info2.hapPath = std::string(Constants::ABS_CODE_PATH) + "/img";
    AbilityInfo info3 = {};
    info3.name = "abilityName2";
    info3.hapPath = "";
    BundleInfo bundleInfo = {};
    bundleInfo.abilityInfos.push_back(info1);
    bundleInfo.abilityInfos.push_back(info2);
    bundleInfo.abilityInfos.push_back(info3);
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo1);
    bundleInfo.applicationInfo.moduleInfos.push_back(moduleInfo2);
    FormInfo formInfo = {};
    formInfo.abilityName = "abilityName1";
    formInfo.moduleName = "moduleName1";
    FormItemInfo itemInfo = {};
    Want want = {};
    MockGetCallerBundleName(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.CreateFormItemInfo(bundleInfo, formInfo, itemInfo, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0152 end";
}

/**
 * @tc.name: FormMgrAdapter_0153
 * @tc.desc: test CheckPublishForm function and the return value is ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0153, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0153 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTaskCheckIsSystemAppByUid = [] (const int uid) {
        GTEST_LOG_(INFO) << "FormMgrAdapter_0153 bmsTaskCheckIsSystemAppByUid called";
        return false;
    };
    EXPECT_CALL(*bmsProxy, CheckIsSystemAppByUid(_)).Times(1).WillOnce(Invoke(bmsTaskCheckIsSystemAppByUid));
    FormMgrAdapter formMgrAdapter;
    Want want = {};

    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.CheckPublishForm(want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0153 end";
}

/**
 * @tc.name: FormMgrAdapter_0154
 * @tc.desc: test CheckPublishForm function and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0154, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0154 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    int32_t times = 0;
    constexpr int32_t counts = 2;
    auto bmsTaskCheckIsSystemAppByUid = [&times, counts] (const int uid) {
        GTEST_LOG_(INFO) << "FormMgrAdapter_0154 bmsTaskCheckIsSystemAppByUid called";
        return !(++times == counts);
    };
    EXPECT_CALL(*bmsProxy, CheckIsSystemAppByUid(_)).Times(1).WillOnce(Invoke(bmsTaskCheckIsSystemAppByUid));
    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = "name";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0154 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetNameForUid(_, _)).Times(1).WillOnce(Invoke(bmsTaskGetBundleNameForUid));
    FormMgrAdapter formMgrAdapter;
    Want want = {};

    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrAdapter.CheckPublishForm(want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0154 end";
}

/**
 * @tc.name: FormMgrAdapter_0155
 * @tc.desc: test QueryPublishFormToHost function and the return value is ERR_APPEXECFWK_FORM_GET_HOST_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0155, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0155 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockGetAbilityInfo(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, formMgrAdapter.QueryPublishFormToHost(want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0155 end";
}

/**
 * @tc.name: FormMgrAdapter_0156
 * @tc.desc: test RequestPublishFormToHost function and the return value is ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0156, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockConnectServiceAbility(false);
    EXPECT_NE(formMgrAdapter.RequestPublishFormToHost(want), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 end";
}

/**
 * @tc.name: FormMgrAdapter_0157
 * @tc.desc: test CheckAddRequestPublishForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0157, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0157 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    want.SetElementName("bundle1", "ability1");
    Want formWant = {};
    formWant.SetElementName("bundle2", "ability2");
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.CheckAddRequestPublishForm(want, formWant));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0157 end";
}

/**
 * @tc.name: FormMgrAdapter_0158
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0158, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0158 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0;
    const Want want = {};
    const sptr<IRemoteObject> &callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0158 end";
}

/**
 * @tc.name: FormMgrAdapter_0159
 * @tc.desc: test HandleUpdateFormFlag function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0159, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0159 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    const sptr<IRemoteObject> &callerToken = nullptr;
    bool flag = false;
    bool isOnlyEnableUpdate = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.HandleUpdateFormFlag(formIds, callerToken, flag, isOnlyEnableUpdate));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0159 end";
}

/**
 * @tc.name: FormMgrAdapter_0160
 * @tc.desc: test AcquireProviderFormInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0160, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0160 start";
    FormMgrAdapter formMgrAdapter;
    const sptr<IRemoteObject> &callerToken = nullptr;
    const Want want = {};
    constexpr int64_t formId = 0;
    formMgrAdapter.AcquireProviderFormInfo(formId, want, callerToken);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0160 end";
}

/**
 * @tc.name: FormMgrAdapter_0161
 * @tc.desc: test NotifyFormDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0161, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0161 start";
    FormMgrAdapter formMgrAdapter;
    const sptr<IRemoteObject> &callerToken = nullptr;
    const Want want = {};
    constexpr int64_t formId = 0;
    formMgrAdapter.NotifyFormDelete(formId, want, callerToken);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0161 end";
}

/**
 * @tc.name: FormMgrAdapter_0162
 * @tc.desc: test NotifyFormsVisible function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0162, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0162 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    bool isVisible = false;
    const sptr<IRemoteObject> &callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.NotifyFormsVisible(formIds, isVisible, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0162 end";
}

/**
 * @tc.name: FormMgrAdapter_0163
 * @tc.desc: test NotifyFormsEnableUpdate function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0163, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0163 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    bool isEnableUpdate = false;
    const sptr<IRemoteObject> &callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0163 end";
}

/**
 * @tc.name: FormMgrAdapter_0164
 * @tc.desc: test GetAllFormsInfo function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0164, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0164 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formMgrAdapter.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0164 end";
}

/**
 * @tc.name: FormMgrAdapter_0165
 * @tc.desc: test GetFormsInfoByApp function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0165, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0165 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<FormInfo> formInfos;
    const std::string bundleName = "";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0165 end";
}

/**
 * @tc.name: FormMgrAdapter_0166
 * @tc.desc: test GetFormsInfoByModule function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0166, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0166 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<FormInfo> formInfos;
    const std::string moudleName = "";
    const std::string bundleName = "";
    EXPECT_EQ(ERR_OK, formMgrAdapter.GetFormsInfoByModule(bundleName, moudleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0166 end";
}

/**
 * @tc.name: FormMgrAdapter_0167
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0167, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0167 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0;
    const Want want = {};
    const sptr<IRemoteObject> &callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0167 end";
}

/**
 * @tc.name: FormMgrAdapter_0168
 * @tc.desc: test checkFormHostHasSaUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0168, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0168 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord = {};
    EXPECT_FALSE(formMgrAdapter.checkFormHostHasSaUid(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0168 end";
}

/**
 * @tc.name: FormMgrAdapter_0169
 * @tc.desc: test checkFormHostHasSaUid function and the return value is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0169, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0169 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord = {};
    constexpr int32_t systemUid = 1000;   // 1000: system uid
    formRecord.formUserUids.push_back(systemUid);
    EXPECT_TRUE(formMgrAdapter.checkFormHostHasSaUid(formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0169 end";
}

/**
 * @tc.name: FormMgrAdapter_0170
 * @tc.desc: test SetNextRefreshTime function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0170, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0170 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(false);
    MockGetFormRecordParamsSysUid(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0170 end";
}

/**
 * @tc.name: FormMgrAdapter_0171
 * @tc.desc: test SetNextRefreshTime function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0171, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0171 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockGetFormRecordParamsUid(true);
    MockGetFormRecordParamsSysUid(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0171 end";
}

/**
 * @tc.name: FormMgrAdapter_0172
 * @tc.desc: test QueryPublishFormToHost function and the return value is ERR_APPEXECFWK_FORM_GET_HOST_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0172, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0172 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockGetAbilityInfo(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, formMgrAdapter.QueryPublishFormToHost(want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0172 end";
}

/**
 * @tc.name: FormMgrAdapter_0173
 * @tc.desc: test QueryPublishFormToHost function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0173, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0173 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockGetAbilityInfo(true);
    MockGetAbilityInfoByAction(true);
    MockGetAbilityInfoByActionAbilityInfo(false);
    MockGetAbilityInfoByActionExtensionInfo(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.QueryPublishFormToHost(want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0173 end";
}

/**
 * @tc.name: FormMgrAdapter_0174
 * @tc.desc: test QueryPublishFormToHost function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0174, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0174 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockGetAbilityInfo(true);
    MockGetAbilityInfoByAction(true);
    MockGetAbilityInfoByActionAbilityInfo(true);
    MockGetAbilityInfoByActionExtensionInfo(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.QueryPublishFormToHost(want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0174 end";
}

/**
 * @tc.name: FormMgrAdapter_0175
 * @tc.desc: test CheckAddRequestPublishForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0175, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0175 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    want.SetElementName("bundle", "ability");
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 2);
    Want formWant = {};
    formWant.SetElementName("bundle", "ability");
    formWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.CheckAddRequestPublishForm(want, formWant));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0175 end";
}

/**
 * @tc.name: FormMgrAdapter_0176
 * @tc.desc: test CheckAddRequestPublishForm function and the return value is ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0176, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0176 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    want.SetElementName("bundle", "ability");
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 2);
    Want formWant = {};
    formWant.SetElementName("bundle", "ability");
    formWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 2);
    MockGetBoolParam(true);
    MockCheckTempEnoughForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, formMgrAdapter.CheckAddRequestPublishForm(want, formWant));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0176 end";
}

/**
 * @tc.name: FormMgrAdapter_0177
 * @tc.desc: test AddRequestPublishForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0177, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0177 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo formItemInfo;
    Want want = {};
    want.SetElementName("bundle", "ability");
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    MockGetRequestPublishFormInfo(false);
    MockGetRequestPublishFormInfoWant(want);
    MockCheckTempEnoughForm(false);
    MockAllotFormHostRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0177 end";
}

/**
 * @tc.name: FormMgrAdapter_0178
 * @tc.desc: test EnableUpdateForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0178, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0178 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIDs;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.EnableUpdateForm(formIDs, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0178 end";
}

/**
 * @tc.name: FormMgrAdapter_0179
 * @tc.desc: test DisableUpdateForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0179, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0179 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIDs;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DisableUpdateForm(formIDs, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0179 end";
}

/**
 * @tc.name: FormMgrAdapter_0180
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0180, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0180 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> &callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0180 end";
}

/**
 * @tc.name: FormMgrAdapter_0181
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0181, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0181 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> &callerToken = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0181 end";
}

/**
 * @tc.name: FormMgrAdapter_0182
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0182, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0182 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want = {};
    const sptr<IRemoteObject> &callerToken = new (std::nothrow) MockFormProviderClient();
    const std::string keyValue = "true";
    want.SetParam(Constants::PARAM_MESSAGE_KEY, keyValue);
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0182 end";
}

/**
 * @tc.name: FormMgrAdapter_0183
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0183, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0183 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want = {};
    const sptr<IRemoteObject> &callerToken = new (std::nothrow) MockFormProviderClient();
    const std::string keyValue = "true";
    want.SetParam(Constants::PARAM_MESSAGE_KEY, keyValue);
    MockGetFormRecord(true);
    MockGetMatchedHostClient(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0183 end";
}

/**
 * @tc.name: FormMgrAdapter_0184
 * @tc.desc: test MessageEvent function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0184, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0184 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int64_t invalidFormId = 0;
    Want want = {};
    const sptr<IRemoteObject> &callerToken = new (std::nothrow) MockFormProviderClient();
    const std::string keyValue = "true";
    want.SetParam(Constants::PARAM_MESSAGE_KEY, keyValue);
    MockGetFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockGetMatchedHostClientParamsMatchedId(invalidFormId);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.MessageEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0184 end";
}

/**
 * @tc.name: FormMgrAdapter_0185
 * @tc.desc: test AcquireFormStateCheck function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0185, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0185 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string abilityName = "aa";
    std::string provider = "";
    Want want;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0185 end";
}

/**
 * @tc.name: FormMgrAdapter_0186
 * @tc.desc: test RouterEvent function and the return value is ERR_INVALID_VALUE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0186, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0186 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityWithSpecifyTokenId_ = ERR_INVALID_VALUE;
    FormAmsHelper::GetInstance().abilityManager_ = mockAmsMgr;
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_INVALID_VALUE, formMgrAdapter.RouterEvent(formId, want, callerToken));
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsHelperBackup;
    FormAmsHelper::GetInstance().abilityManager_ = amsHelperBackup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0186 end";
}

/**
 * @tc.name: FormMgrAdapter_0187
 * @tc.desc: test RouterEvent function and the return value is ERR_INVALID_VALUE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0187, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0187 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityWithSpecifyTokenId_ = ERR_INVALID_VALUE;
    FormAmsHelper::GetInstance().abilityManager_ = mockAmsMgr;
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    want.SetBundle("bundle");
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_INVALID_VALUE, formMgrAdapter.RouterEvent(formId, want, callerToken));
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsHelperBackup;
    FormAmsHelper::GetInstance().abilityManager_ = amsHelperBackup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0187 end";
}

/**
 * @tc.name: FormMgrAdapter_0188
 * @tc.desc: test RouterEvent function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0188, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0188 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;

    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityWithSpecifyTokenId_ = ERR_OK;
    FormAmsHelper::GetInstance().abilityManager_ = mockAmsMgr;
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    want.SetBundle("bundle");
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockGetFormRecord(true);
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.RouterEvent(formId, want, callerToken));
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsHelperBackup;
    FormAmsHelper::GetInstance().abilityManager_ = amsHelperBackup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0188 end";
}

/**
 * @tc.name: FormMgrAdapter_0189
 * @tc.desc: test NotifyFormDelete function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0189, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0189 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    want.SetBundle("bundle");
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formMgrAdapter.NotifyFormDelete(formId, want, callerToken);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0189 end";
}

/**
 * @tc.name: FormMgrAdapter_0190
 * @tc.desc: test DeleteInvalidForms function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0190, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0190 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    formIds.push_back(1);
    formIds.push_back(2);
    formIds.push_back(3);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(ERR_OK, formMgrAdapter.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0190 end";
}

/**
 * @tc.name: FormMgrAdapter_192
 * @tc.desc: test IsValidPublishEvent function and the return value is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_192, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_192 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));
    std::string bundleName = "com.ohos.launcher";
    EXPECT_EQ(true, formMgrAdapter.IsValidPublishEvent(bmsProxy, bundleName, want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_192 end";
}

/**
 * @tc.name: FormMgrAdapter_193
 * @tc.desc: test IsValidPublishEvent function and the return value is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_193, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_193 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());

    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));
    std::string bundleName = "com.ohos.launcher";
    EXPECT_EQ(true, formMgrAdapter.IsValidPublishEvent(bmsProxy, bundleName, want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_193 end";
}

/**
 * @tc.name: FormMgrAdapter_194
 * @tc.desc: test IsValidPublishEvent function and the return value is false when rule allow.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_194, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_194 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());

    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));
    std::string bundleName = "com.ohos.launcher";
    EXPECT_EQ(true, formMgrAdapter.IsValidPublishEvent(bmsProxy, bundleName, want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_194 end";
}

/**
 * @tc.name: FormMgrAdapter_0195
 * @tc.desc: test AcquireFormData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0195, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0195 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t requestCode = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    AAFwk::WantParams formData;
    EXPECT_EQ(ERR_OK, formMgrAdapter.AcquireFormData(formId, requestCode, callerToken, formData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0195 end";
}
/**
 * @tc.name: FormMgrAdapter_196
 * @tc.desc: test DumpTemporaryFormInfos function and the return failed when temp form count is zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_196, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_196 start";
    // Clear all formRecords in FormDataMgr
    FormDataMgr::GetInstance().formRecords_.clear();
    // DumpTemporaryFormInfos
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpTemporaryFormInfos(formInfos));

    GTEST_LOG_(INFO) << "FormMgrAdapter_196 end";
}

/**
 * @tc.name: FormMgrAdapter_197
 * @tc.desc: test DumpTemporaryFormInfos function and the return OK when temp form count is not zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_197, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_197 start";
    // Add temp formRecords to FormDataMgr
    FormDataMgr::GetInstance().formRecords_.clear();
    FormRecord formRecord;
    formRecord.formTempFlag = true;
    FormDataMgr::GetInstance().formRecords_.emplace(0, formRecord);
    // DumpTemporaryFormInfos
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpTemporaryFormInfos(formInfos));
    EXPECT_EQ(false, formInfos.empty());

    GTEST_LOG_(INFO) << "FormMgrAdapter_197 end";
}

/**
 * @tc.name: FormMgrAdapter_198
 * @tc.desc: test DumpStaticBundleFormInfos function and the return OK when temp form count is not zero.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_198, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_198 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpStaticBundleFormInfos(formInfos));
    EXPECT_EQ(false, formInfos.empty());

    GTEST_LOG_(INFO) << "FormMgrAdapter_198 end";
}

/**
 * @tc.name: FormMgrAdapter_199
 * @tc.desc: test HandleFormAddObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_199, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_199 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    MockGetCallerBundleName(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.HandleFormAddObserver(formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_199 end";
}

/**
 * @tc.name: FormMgrAdapter_200
 * @tc.desc: test HandleFormAddObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_200 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    MockGetCallerBundleName(false);
    MockGetRunningFormInfosByFormId(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleFormAddObserver(formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_200 end";
}

/**
 * @tc.name: FormMgrAdapter_201
 * @tc.desc: test HandleFormRemoveObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_201, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_201 start";
    FormMgrAdapter formMgrAdapter;
    MockGetCallerBundleName(false);
    RunningFormInfo runningFormInfo;
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleFormRemoveObserver(runningFormInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_201 end";
}

/**
 * @tc.name: FormMgrAdapter_202
 * @tc.desc: test HandleFormRemoveObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_202, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_202 start";
    FormMgrAdapter formMgrAdapter;
    MockGetCallerBundleName(true);
    RunningFormInfo runningFormInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.HandleFormRemoveObserver(runningFormInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_202 end";
}

/**
 * @tc.name: FormMgrAdapter_203
 * @tc.desc: test RegisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_203, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_203 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RegisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_203 end";
}

/**
 * @tc.name: FormMgrAdapter_204
 * @tc.desc: test RegisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_204, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_204 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback;
    auto interceptor = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RegisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_204 end";
}

/**
 * @tc.name: FormMgrAdapter_205
 * @tc.desc: test RegisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_205, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_205 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback;
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RegisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_205 end";
}

/**
 * @tc.name: FormMgrAdapter_206
 * @tc.desc: test UnregisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_206, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_206 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback;
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UnregisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_206 end";
}

/**
 * @tc.name: FormMgrAdapter_207
 * @tc.desc: test UnregisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_207, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_207 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback;
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UnregisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_207 end";
}

/**
 * @tc.name: FormMgrAdapter_208
 * @tc.desc: test UnregisterPublishFormInterceptor function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_208, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_208 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IRemoteObject> interceptorCallback;
    auto interceptor = iface_cast<AppExecFwk::IFormPublishInterceptor>(interceptorCallback);
    auto formPublishInterceptor_ = interceptor;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UnregisterPublishFormInterceptor(interceptorCallback));
    GTEST_LOG_(INFO) << "FormMgrAdapter_208 end";
}

/**
 * @tc.name: FormMgrAdapter_209
 * @tc.desc: test BackGroundEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_209, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_209 start";
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityByCall_ = ERR_OK;
    FormAmsHelper::GetInstance().abilityManager_ = mockAmsMgr;
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    want.SetBundle("bundle");
    nlohmann::json params;
    params[Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY] = "test";
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, params.dump());
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.BackgroundEvent(formId, want, callerToken));
    FormAmsHelper::GetInstance().abilityManager_ = amsHelperBackup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_209 end";
}

/**
 * @tc.name: FormMgrAdapter_210
 * @tc.desc: test BackGroundEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_210, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_210 start";
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityByCall_ = ERR_OK;
    FormAmsHelper::GetInstance().abilityManager_ = mockAmsMgr;
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    want.SetBundle("bundle");
    nlohmann::json params;
    params[Constants::PARAM_FORM_CALL_EVENT_METHOD_KEY] = 1;
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, params.dump());
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.BackgroundEvent(formId, want, callerToken));
    FormAmsHelper::GetInstance().abilityManager_ = amsHelperBackup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_210 end";
}

/**
 * @tc.name: FormMgrAdapter_211
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_211, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_211 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(false);
    EXPECT_EQ(false, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_211 end";
}

/**
 * @tc.name: FormMgrAdapter_212
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_212, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_212 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    EXPECT_EQ(false, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_212 end";
}

/**
 * @tc.name: FormMgrAdapter_213
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_213, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_213 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.apiTargetVersion = 9;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_213 end";
}

/**
 * @tc.name: FormMgrAdapter_214
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_214, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_214 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.apiTargetVersion = 11;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_214 end";
}

/**
 * @tc.name: FormMgrAdapter_215
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_215, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_215 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.apiTargetVersion = 11;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    std::string additionalInfo = "";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_TIMED_OUT)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);

    additionalInfo = "";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);

    additionalInfo = "abcdefg";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);

    additionalInfo = "formUpdateLevel:dfd";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);

    additionalInfo = "formUpdateLevel:0";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 2 * Constants::TIME_CONVERSION);

    additionalInfo = "formUpdateLevel:4, time:0, formUpdateLevel:7";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 7 * Constants::TIME_CONVERSION);

    additionalInfo = "formUpdateLevel:4, time:0, formUpdateLevel:1111";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));
    formMgrAdapter.UpdateFormCloudUpdateDuration("bundleName");
    EXPECT_EQ(true, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    EXPECT_EQ(updateDuration, 4 * Constants::TIME_CONVERSION);

    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_215 end";
}

/**
 * @tc.name: FormMgrAdapter_216
 * @tc.desc: test RegisterFormRouterProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_216, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_216 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(ERR_OK, formMgrAdapter.RegisterFormRouterProxy(formIds, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_216 end";
}

/**
 * @tc.name: FormMgrAdapter_217
 * @tc.desc: test RegisterFormRouterProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_217, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_217 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_INVALID_PARAM);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RegisterFormRouterProxy(formIds, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_217 end";
}

/**
 * @tc.name: FormMgrAdapter_218
 * @tc.desc: test RegisterFormRouterProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_218, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_218 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RegisterFormRouterProxy(formIds, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_218 end";
}


/**
 * @tc.name: FormMgrAdapter_219
 * @tc.desc: test UnregisterFormRouterProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_219, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_219 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrAdapter.UnregisterFormRouterProxy(formIds));
    GTEST_LOG_(INFO) << "FormMgrAdapter_219 end";
}

/**
 * @tc.name: FormMgrAdapter_220
 * @tc.desc: test UnregisterFormRouterProxy function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_220, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_220 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_INVALID_PARAM);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UnregisterFormRouterProxy(formIds));
    GTEST_LOG_(INFO) << "FormMgrAdapter_220 end";
}

/**
 * @tc.name: FormMgrAdapter_221
 * @tc.desc: test GetFormInstancesByFilter function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_221, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_221 start";
    FormMgrAdapter formMgrAdapter;

    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrAdapter_221 end";
}

/**
 * @tc.name: FormMgrAdapter_222
 * @tc.desc: test GetFormInstanceById function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_222, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_222 start";
    FormMgrAdapter formMgrAdapter;

    FormInstancesFilter formInstancesFilter;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.GetFormInstanceById(1, formInstance));
    GTEST_LOG_(INFO) << "FormMgrAdapter_222 end";
}

/**
 * @tc.name: FormMgrAdapter_223
 * @tc.desc: test DumpFormRunningForminfos function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_223, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_223 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    MockGetRunningFormInfos(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormRunningFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_223 end";
}

/**
 * @tc.name: FormMgrAdapter_224
 * @tc.desc: test DumpFormInfoByFormId function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_224, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_224 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfo = "aa";
    MockGetRunningFormInfos(ERR_NONE);
    EXPECT_EQ(ERR_NONE, formMgrAdapter.DumpFormRunningFormInfos(formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_224 end";
}

/**
 * @tc.name: FormMgrAdapter_225
 * @tc.desc: test GetFormsInfoByFilter function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_225, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_225 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    EXPECT_EQ(ERR_OK, formMgrAdapter.GetFormsInfoByFilter(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_225 end";
}

/**
 * @tc.number: FormMgrAdapter_226
 * @tc.name: UpdateFormLocation
 * @tc.desc: Verify that the map can be operated normally.
 * @tc.details: Determine whether an element exists in the map.
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_226, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_226 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t formLocation = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.UpdateFormLocation(formId, formLocation));
    GTEST_LOG_(INFO) << "FormMgrAdapter_226 end";
}

/**
 * @tc.number: FormMgrAdapter_227
 * @tc.name: SetPublishFormResult
 * @tc.desc: test SetPublishFormResult function.
 * @tc.details: Validating results in different scenarios.
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_227, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_227 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(formMgrAdapter.SetPublishFormResult(formId, result), ERR_APPEXECFWK_FORM_COMMON_CODE);

    formMgrAdapter.serialQueue_ = std::make_shared<FormSerialQueue>("FormMgrTimerTaskQueueTest");
    EXPECT_EQ(formMgrAdapter.SetPublishFormResult(formId, result), ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::UNKNOWN));
    EXPECT_EQ(formMgrAdapter.SetPublishFormResult(formId, result), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrAdapter_227 end";
}

/**
 * @tc.number: FormMgrAdapter_228
 * @tc.name: AcquireAddFormResult
 * @tc.desc: test AcquireAddFormResult function.
 * @tc.details: Verify that the results can be obtained in different scenarios.
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_228, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_228 start";
    FormMgrAdapter formMgrAdapter;
    const int64_t formId1 = 1;
    formMgrAdapter.condition_.notify_all();
    EXPECT_EQ(formMgrAdapter.AcquireAddFormResult(formId1), ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    formMgrAdapter.formIdMap_.insert(std::make_pair(formId1, AddFormResultErrorCode::SUCCESS));
    formMgrAdapter.condition_.notify_all();
    EXPECT_EQ(formMgrAdapter.AcquireAddFormResult(formId1), ERR_OK);

    const int64_t formId2 = 2;
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId2, AddFormResultErrorCode::FAILED));
    formMgrAdapter.condition_.notify_all();
    EXPECT_EQ(formMgrAdapter.AcquireAddFormResult(formId2), ERR_APPEXECFWK_FORM_COMMON_CODE);

    const int64_t formId3 = 3;
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId3, AddFormResultErrorCode::TIMEOUT));
    formMgrAdapter.condition_.notify_all();
    EXPECT_EQ(formMgrAdapter.AcquireAddFormResult(formId3), ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT);

    const int64_t formId4 = 4;
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId4, AddFormResultErrorCode::UNKNOWN));
    GTEST_LOG_(INFO) << "notify UNKNOWN status";
    formMgrAdapter.condition_.notify_all();
    std::thread setResultThread ([formId4, &formMgrAdapter] {
        std::lock_guard<std::mutex> lock(formMgrAdapter.formResultMutex_);
        formMgrAdapter.formIdMap_[formId4] = AddFormResultErrorCode::SUCCESS;
        GTEST_LOG_(INFO) << "notify SUCCESS status";
        formMgrAdapter.condition_.notify_all();
    });
    EXPECT_EQ(formMgrAdapter.AcquireAddFormResult(formId4), ERR_OK);
    GTEST_LOG_(INFO) << "Acquire no UNKNOWN status";
    setResultThread.join();

    GTEST_LOG_(INFO) << "FormMgrAdapter_228 end";
}

/**
 * @tc.name: FormMgrAdapter_229
 * @tc.desc: test SetTimerTaskNeeded function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_229, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_229 start";
    FormMgrAdapter formMgrAdapter;
    formMgrAdapter.SetTimerTaskNeeded(false);
    GTEST_LOG_(INFO) << "FormMgrAdapter_229 end";
}

/**
 * @tc.name: FormMgrAdapter_230
 * @tc.desc: test SetTimerTaskNeeded function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_230, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_230 start";
    FormMgrAdapter formMgrAdapter;
    formMgrAdapter.SetTimerTaskNeeded(true);
    GTEST_LOG_(INFO) << "FormMgrAdapter_230 end";
}
}
