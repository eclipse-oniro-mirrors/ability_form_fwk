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
#include "common/util/form_util.h"
#include "form_render/form_render_mgr.h"
#define private public
#include "form_mgr/form_mgr_adapter.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "mock_ability_manager.h"
#include "mock_bundle_mgr.h"
#include "mock_form_provider_client.h"
#include "inner/mock_form_refresh_mgr.h"

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
extern void MockGetFormRecord(bool mockRet);
extern void MockGetFormRecordParams(bool mockRet);
extern void MockGetFormRecordParamsUid(bool mockRet);
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
    MockRequestRefreshRet(true);
    FormDataProxy formDataProxy("key", "id");
    EXPECT_EQ(ERR_OK, formMgrAdapter.UpdateForm(formId, uid, formProviderData, {formDataProxy}));
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
    MockGetFormRecord(false);
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
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
    MockGetFormRecord(true);
    MockRequestRefreshRet(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
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
    MockGetFormRecord(true);
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
    MockGetFormRecord(true);
    MockRequestRefreshRet(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_084 end";
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
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
 * @tc.name: FormMgrAdapter_0103_0
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_0, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_0 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::FAILED));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_0 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_1
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_1, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_1 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
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
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_1 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_1 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_2
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_2, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_2 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(false);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_2 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_2 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_3
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_3, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_3 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_3 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_3 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_4
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_4, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_4 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_4 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_4 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_5
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_5, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_5 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    std::string bundleName = "bundleName";
    ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "bundleName";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_5 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_5 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_6
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_6, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_6 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_6 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_6 end";
}

/**
 * @tc.name: FormMgrAdapter_0103_7
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0103_7, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_7 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0103_7 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::UNKNOWN));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0103_7 end";
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
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
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
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteForm(formId, callerToken));
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
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
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
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0116 end";
}

/**
 * @tc.name: FormMgrAdapter_0116_1
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
 HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0116_1, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0116_1 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockHasFormUserUids(false);
     MockNotifyProviderFormDelete(false);
     MockDeleteHostRecord(false);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
     GTEST_LOG_(INFO) << "FormMgrAdapter_0116_1 end";
 }
 
 /**
  * @tc.name: FormMgrAdapter_0116_2
  * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0116_2, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0116_2 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockHasFormUserUids(false);
     MockNotifyProviderFormDelete(true);
     MockDeleteHostRecord(false);
     formMgrAdapter.HandleDeleteTempForm(formId, callerToken);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0116_2 end";
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
 * @tc.desc: test HandleEventNotify function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0121, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0121 start";
    FormMgrAdapter formMgrAdapter;
    std::string providerKey = "aa";
    std::vector<int64_t> formIdsByProvider;
    int32_t formVisibleType = 1;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formMgrAdapter.HandleEventNotify(providerKey, formIdsByProvider, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0121 end";
}

/**
 * @tc.name: FormMgrAdapter_0122
 * @tc.desc: test HandleEventNotify function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0122, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0122 start";
    FormMgrAdapter formMgrAdapter;
    std::string providerKey = "aa";
    std::vector<int64_t> formIdsByProvider;
    int32_t formVisibleType = 1;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleEventNotify(providerKey, formIdsByProvider, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0122 end";
}

/**
 * @tc.name: FormMgrAdapter_0123
 * @tc.desc: test AcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0123, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0123 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    FormItemInfo info;
    WantParams wantParams;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0123 end";
}

/**
 * @tc.name: FormMgrAdapter_0124
 * @tc.desc: test AcquireProviderFormInfoAsync function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0124, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0124 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formMgrAdapter.AcquireProviderFormInfoAsync(formId, info, wantParams));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0124 end";
}

/**
 * @tc.name: FormMgrAdapter_0125
 * @tc.desc: test GetFormItemInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0125, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0125 start";
    FormMgrAdapter formMgrAdapter;
    AAFwk::Want want;
    BundleInfo bundleInfo;
    FormInfo formInfo;
    FormItemInfo formItemInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION,
        formMgrAdapter.GetFormItemInfo(want, bundleInfo, formInfo, formItemInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0125 end";
}

/**
 * @tc.name: FormMgrAdapter_0126
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0126, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0126 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    int64_t nextTime = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0126 end";
}

/**
 * @tc.name: FormMgrAdapter_0127
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0127, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0127 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetFormRecord(true);
    MockRequestRefreshRet(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0127 end";
}

/**
 * @tc.name: FormMgrAdapter_0128
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0128, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0128 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetUidByBundleName(false);
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0128 end";
}

/**
 * @tc.name: FormMgrAdapter_0129
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0129, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0129 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetUidByBundleName(false);
    MockGetFormRecord(true);
    formMgrAdapter.SetNextRefreshTime(formId, nextTime);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0129 end";
}

/**
 * @tc.name: FormMgrAdapter_0130
 * @tc.desc: test AddRequestPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0130, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0130 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo formItemInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    MockGetRequestPublishFormInfo(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
        formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0130 end";
}

/**
 * @tc.name: FormMgrAdapter_0131
 * @tc.desc: test AddRequestPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0131, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0131 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo formItemInfo;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;
    MockGetRequestPublishFormInfo(false);
    formMgrAdapter.AddRequestPublishForm(formItemInfo, want, callerToken, formJsInfo);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0131 end";
}

/**
 * @tc.name: FormMgrAdapter_0132
 * @tc.desc: test IsRequestPublishFormSupported function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0132, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0132 start";
    FormMgrAdapter formMgrAdapter;
    MockGetAbilityInfoByAction(true);
    EXPECT_EQ(false, formMgrAdapter.IsRequestPublishFormSupported());
    GTEST_LOG_(INFO) << "FormMgrAdapter_0132 end";
}

/**
 * @tc.name: FormMgrAdapter_0133
 * @tc.desc: test IsRequestPublishFormSupported function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0133, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0133 start";
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
    GTEST_LOG_(INFO) << "FormMgrAdapter_0133 end";
}

/**
 * @tc.name: FormMgrAdapter_0134
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0134, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0134 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string abilityName = "";
    Want want;
    std::string provider = "";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0134 end";
}

/**
 * @tc.name: FormMgrAdapter_0135
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0135, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0135 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string abilityName = "aa";
    Want want;
    std::string provider = "";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string());
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string());
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.AcquireFormStateCheck(bundleName, abilityName, want, provider));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0135 end";
}

/**
 * @tc.name: FormMgrAdapter_0136
 * @tc.desc: test AcquireFormStateCheck function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0136, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0136 start";
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
    GTEST_LOG_(INFO) << "FormMgrAdapter_0136 end";
}

/**
 * @tc.name: FormMgrAdapter_0137
 * @tc.desc: test AcquireFormState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0137, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0137 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireFormState(want, callerToken, stateInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0137 end";
}

/**
 * @tc.name: FormMgrAdapter_0138
 * @tc.desc: test AcquireFormState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0138, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0138 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormStateInfo stateInfo;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AcquireFormState(want, callerToken, stateInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0138 end";
}

/**
 * @tc.name: FormMgrAdapter_0139
 * @tc.desc: test IsUpdateValid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0139, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0139 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    std::string bundleName = "";
    EXPECT_EQ(false, formMgrAdapter.IsUpdateValid(formId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0139 end";
}

/**
 * @tc.name: FormMgrAdapter_0140
 * @tc.desc: test IsUpdateValid function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0140, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0140 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::string bundleName = "aa";
    EXPECT_EQ(true, formMgrAdapter.IsUpdateValid(formId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0140 end";
}

/**
 * @tc.name: FormMgrAdapter_0141
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0141, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0141 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RouterEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0141 end";
}

/**
 * @tc.name: FormMgrAdapter_0142
 * @tc.desc: test RouterEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0142, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0142 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.RouterEvent(formId, want, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0142 end";
}

/**
 * @tc.name: FormMgrAdapter_0143
 * @tc.desc: test IsFormCached function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0143, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0143 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord record;
    record.versionUpgrade = true;
    EXPECT_EQ(false, formMgrAdapter.IsFormCached(record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0143 end";
}

/**
 * @tc.name: FormMgrAdapter_0144
 * @tc.desc: test IsFormCached function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0144, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0144 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord record;
    record.versionUpgrade = false;
    EXPECT_EQ(true, formMgrAdapter.IsFormCached(record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0144 end";
}

/**
 * @tc.name: FormMgrAdapter_0145
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0145, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0145 start";
    FormMgrAdapter formMgrAdapter;
    int64_t matchedFormId = 1;
    FormRecord formRecord;
    formRecord.formVisibleNotify = false;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    EXPECT_EQ(false, formMgrAdapter.CreateHandleEventMap(matchedFormId, formRecord, eventMaps));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0145 end";
}

/**
 * @tc.name: FormMgrAdapter_0146
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0146, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0146 start";
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
    GTEST_LOG_(INFO) << "FormMgrAdapter_0146 end";
}

/**
 * @tc.name: FormMgrAdapter_0147
 * @tc.desc: test CreateHandleEventMap function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0147, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0147 start";
    FormMgrAdapter formMgrAdapter;
    int64_t matchedFormId = 1;
    FormRecord formRecord;
    formRecord.formVisibleNotify = true;
    formRecord.bundleName = "aa";
    formRecord.abilityName = "bb";
    std::map<std::string, std::vector<int64_t>> eventMaps;
    EXPECT_EQ(true, formMgrAdapter.CreateHandleEventMap(matchedFormId, formRecord, eventMaps));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0147 end";
}

/**
 * @tc.name: FormMgrAdapter_0148
 * @tc.desc: test DeleteInvalidForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0148, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 end";
}

/**
 * @tc.name: FormMgrAdapter_0149
 * @tc.desc: test DeleteInvalidForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0149, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0149 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(ERR_OK, formMgrAdapter.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0149 end";
}

/**
 * @tc.name: FormMgrAdapter_0150
 * @tc.desc: test DeleteForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0150, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0150 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockExistTempForm(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0150 end";
}
/**
 * @tc.name: FormMgrAdapter_0151
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0151, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0151 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(true);
    MockGetFormRecord(true);
    MockCheckTempEnoughForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0151 end";
}

/**
 * @tc.name: FormMgrAdapter_0152
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0152, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0152 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo;
    MockGetBoolParam(false);
    MockCheckTempEnoughForm(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0152 end";
}

/**
 * @tc.name: FormMgrAdapter_0153
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0153, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0153 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0153 end";
}

/**
 * @tc.name: FormMgrAdapter_0154
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0154, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0154 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0154 end";
}

/**
 * @tc.name: FormMgrAdapter_0155
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0155, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0155 start";
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
    GTEST_LOG_(INFO) << "FormMgrAdapter_0155 end";
}

/**
 * @tc.name: FormMgrAdapter_0156
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0156, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    int32_t uid = 1;
    int64_t formId = 2;
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 end";
}

/**
 * @tc.name: FormMgrAdapter_0157
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0157, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0157 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    dbRecord.formUserUids.emplace_back(1);
    int32_t uid = 1;
    int64_t formId = 2;
    MockUpdateDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0157 end";
}

/**
 * @tc.name: FormMgrAdapter_0158
 * @tc.desc: test UpdateForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0158, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0158 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int32_t uid = 1;
    FormProviderData formProviderData;
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.UpdateForm(formId, uid, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0158 end";
}

/**
 * @tc.name: FormMgrAdapter_0159
 * @tc.desc: test RequestForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0159, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0159 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    Want want;
    MockGetFormRecord(true);
    MockRequestRefreshRet(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0159 end";
}

/**
 * @tc.name: FormMgrAdapter_0160
 * @tc.desc: test NotifyWhetherVisibleForms function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0160, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0160 start";
    FormMgrAdapter formMgrAdapter;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t formVisibleType = 2;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0160 end";
}

/**
 * @tc.name: FormMgrAdapter_0161
 * @tc.desc: test NotifyWhetherVisibleForms function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0161, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0161 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t formVisibleType = 2;
    EXPECT_EQ(ERR_OK, formMgrAdapter.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0161 end";
}

/**
 * @tc.name: FormMgrAdapter_0162
 * @tc.desc: test isFormShouldUpdateProviderInfoToHost function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0162, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0162 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    int64_t matchedFormId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t userId = FormUtil::GetCurrentAccountId();
    EXPECT_EQ(false, formMgrAdapter.isFormShouldUpdateProviderInfoToHost(matchedFormId, userId,
        callerToken, formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0162 end";
}

/**
 * @tc.name: FormMgrAdapter_0163
 * @tc.desc: test isFormShouldUpdateProviderInfoToHost function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0163, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0163 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord formRecord;
    int64_t matchedFormId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int32_t userId = FormUtil::GetCurrentAccountId();
    MockGetFormRecord(true);
    EXPECT_EQ(false, formMgrAdapter.isFormShouldUpdateProviderInfoToHost(matchedFormId, userId,
        callerToken, formRecord));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0163 end";
}

/**
 * @tc.name: FormMgrAdapter_0164
 * @tc.desc: test CheckIsSystemAppByBundleName function and the return value is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0164, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0164 start";
    FormMgrAdapter formMgrAdapter;
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    std::string bundleName = "aa";
    int32_t userId = FormUtil::GetCurrentAccountId();
    EXPECT_EQ(false, formMgrAdapter.CheckIsSystemAppByBundleName(iBundleMgr, userId, bundleName));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0164 end";
}

/**
 * @tc.name: FormMgrAdapter_0165
 * @tc.desc: test HandleCastTempForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0165, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0165 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    FormRecord record;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleCastTempForm(formId, record));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0165 end";
}

/**
 * @tc.name: FormMgrAdapter_0166
 * @tc.desc: test DumpStorageFormInfos function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0166, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0166 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos = "";
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpStorageFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0166 end";
}

/**
 * @tc.name: FormMgrAdapter_0167
 * @tc.desc: test DumpStorageFormInfos function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0167, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0167 start";
    FormMgrAdapter formMgrAdapter;
    std::string formInfos;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpStorageFormInfos(formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0167 end";
}

/**
 * @tc.name: FormMgrAdapter_0168
 * @tc.desc: test DumpFormInfoByBundleName function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0168, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0168 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "aa";
    std::string formInfos ;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.DumpFormInfoByBundleName(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0168 end";
}

/**
 * @tc.name: FormMgrAdapter_0169
 * @tc.desc: test DumpFormInfoByBundleName function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0169, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0169 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    std::string formInfos = "";
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_OK, formMgrAdapter.DumpFormInfoByBundleName(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0169 end";
}

/**
 * @tc.name: FormMgrAdapter_0170
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0170, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0170 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0170 end";
}

/**
 * @tc.name: FormMgrAdapter_0171
 * @tc.desc: test AllotFormById function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0171, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0171 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGetFormRecord(false);
    MockGetDBRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0171 end";
}

/**
 * @tc.name: FormMgrAdapter_0172
 * @tc.desc: test AllotFormByInfo function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0172, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0172 start";
    FormMgrAdapter formMgrAdapter;
    FormItemInfo info;
    sptr<IRemoteObject> callerToken = nullptr;
    WantParams wantParams;
    FormJsInfo formInfo;
    MockGenerateFormId(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formMgrAdapter.AllotFormByInfo(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0172 end";
}

/**
 * @tc.name: FormMgrAdapter_0173
 * @tc.desc: test AddForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0173, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0173 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    MockGetBoolParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0173 end";
}

/**
 * @tc.name: FormMgrAdapter_0174
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0174, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0174 start";
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
        GTEST_LOG_(INFO) << "FormMgrAdapter_0174 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0174 end";
}

/**
 * @tc.name: FormMgrAdapter_0175
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0175, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0175 start";
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
        GTEST_LOG_(INFO) << "FormMgrAdapter_0175 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0175 end";
}

/**
 * @tc.name: FormMgrAdapter_0176
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0176, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0176 start";
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
        GTEST_LOG_(INFO) << "FormMgrAdapter_0176 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0176 end";
}

/**
 * @tc.name: FormMgrAdapter_0177
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0177, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0177 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::FAILED));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0177 end";
}

/**
 * @tc.name: FormMgrAdapter_0178
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0178, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0178 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
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
        GTEST_LOG_(INFO) << "FormMgrAdapter_0178 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0178 end";
}

/**
 * @tc.name: FormMgrAdapter_0179
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0179, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0179 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(false);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0179 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0179 end";
}

/**
 * @tc.name: FormMgrAdapter_0180
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0180, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0180 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0180 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0180 end";
}

/**
 * @tc.name: FormMgrAdapter_0181
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0181, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0181 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0181 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0181 end";
}

/**
 * @tc.name: FormMgrAdapter_0182
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0182, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0182 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    std::string bundleName = "bundleName";
    ElementName elementName;
    elementName.SetBundleName(bundleName);
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "bundleName";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0182 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    FormRenderMgr::GetInstance().OnRenderingBlock(bundleName);
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0182 end";
}

/**
 * @tc.name: FormMgrAdapter_0183
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0183, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0183 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(true);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0183 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0183 end";
}

/**
 * @tc.name: FormMgrAdapter_0184
 * @tc.desc: test AddForm function with wrong ability name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0184, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0184 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    constexpr int32_t dimensionId = 1;
    ElementName elementName;
    elementName.SetBundleName("bundleName");
    elementName.SetAbilityName("ability");
    elementName.SetModuleName("aa");
    Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo = {};
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimensionId);
    want.SetElement(elementName);
    MockGetRequestPublishFormInfo(false);
    MockGetCallerBundleName(false);
    MockGetFormsInfoByModule(false);
    MockGetFormsInfoByModuleParam(true);
    MockCheckTempEnoughForm(false);
    MockGetBoolParam(false);
    MockIsRequestPublishForm(false);
    auto bmsTask = [] (const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) {
        std::string moduleName = "aa";
        bundleInfo.moduleNames.push_back(moduleName);
        bundleInfo.name = "aa";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0184 bmsTask called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfoV9(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    formMgrAdapter.formIdMap_.insert(std::make_pair(formId, AddFormResultErrorCode::UNKNOWN));
    EXPECT_NE(formMgrAdapter.AddForm(formId, want, callerToken, formInfo), ERR_OK);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_0184 end";
}

/**
 * @tc.name: FormMgrAdapter_0185
 * @tc.desc: test DeleteForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0185, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0185 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0185 end";
}

/**
 * @tc.name: FormMgrAdapter_0186
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0186, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0186 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = true;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0186 end";
}

/**
 * @tc.name: FormMgrAdapter_0187
 * @tc.desc: test ReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0187, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0187 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = false;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0187 end";
}

/**
 * @tc.name: FormMgrAdapter_0188
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0188, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0188 start";
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
    GTEST_LOG_(INFO) << "FormMgrAdapter_0188 end";
}

/**
 * @tc.name: FormMgrAdapter_0189
 * @tc.desc: test ReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0189, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0189 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    constexpr bool delCache = false;
    MockExistTempForm(false);
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.ReleaseForm(formId, callerToken, delCache));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0189 end";
}

/**
 * @tc.name: FormMgrAdapter_0190
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0190, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0190 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0190 end";
}

/**
 * @tc.name: FormMgrAdapter_0191
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0191, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0191 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(false);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0191 end";
}

/**
 * @tc.name: FormMgrAdapter_0192
 * @tc.desc: test HandleReleaseForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0192, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0192 start";
    FormMgrAdapter formMgrAdapter;
    constexpr int64_t formId = 0x000000007FFFFFFFL;
    sptr<IRemoteObject> callerToken = nullptr;
    MockExistFormRecord(true);
    MockGetMatchedHostClient(true);
    MockGetMatchedHostClientParams(true);
    MockHasFormUserUids(false);
    MockRemoveFormTimer(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrAdapter.HandleReleaseForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0192 end";
}

/**
 * @tc.name: FormMgrAdapter_0193
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0193, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0193 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0193 end";
}

/**
 * @tc.name: FormMgrAdapter_0194
 * @tc.desc: test HandleDeleteForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0194, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0194 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetDBRecord(true);
    MockGetDBRecordParam(true);
    MockDeleteHostRecord(true);
    MockRemoveFormTimer(true);
    MockUpdateDBRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0194 end";
}

/**
 * @tc.name: FormMgrAdapter_0195
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0195, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0195 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0195 end";
}

/**
 * @tc.name: FormMgrAdapter_0196
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0196, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0196 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0196 end";
}

/**
 * @tc.name: FormMgrAdapter_0197
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0197, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0197 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    MockHasFormUserUids(false);
    MockNotifyProviderFormDelete(true);
    MockDeleteHostRecord(true);
    EXPECT_EQ(ERR_OK, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0197 end";
}

/**
 * @tc.name: FormMgrAdapter_0198
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
 HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0198, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0198 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockHasFormUserUids(false);
     MockNotifyProviderFormDelete(false);
     MockDeleteHostRecord(false);
     EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.HandleDeleteTempForm(formId, callerToken));
     GTEST_LOG_(INFO) << "FormMgrAdapter_0198 end";
 }
 
 /**
  * @tc.name: FormMgrAdapter_0201
  * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0201, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0201 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockHasFormUserUids(false);
     MockNotifyProviderFormDelete(true);
     MockDeleteHostRecord(false);
     formMgrAdapter.HandleDeleteTempForm(formId, callerToken);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0201 end";
 }

/**
 * @tc.name: FormMgrAdapter_0199
 * @tc.desc: test HandleDeleteFormCache function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0199, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0199 start";
    FormMgrAdapter formMgrAdapter;
    FormRecord dbRecord;
    int32_t uid = 1;
    int64_t formId = 2;
    MockNotifyProviderFormDelete(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.HandleDeleteFormCache(dbRecord, uid, formId));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0199 end";
}

/**
 * @tc.name: FormMgrAdapter_0200
 * @tc.desc: test RequestForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0200 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.RequestForm(formId, callerToken, want));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0200 end";
}
// Please add to file fms_form_mgr_adapter_test2.cpp
}
