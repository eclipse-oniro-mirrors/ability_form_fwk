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
extern void MockExistFormRecord(bool mockRet);
extern void MockGetMatchedHostClient(bool mockRet);
extern void MockGetMatchedHostClientParams(bool mockRet);
extern void MockGetMatchedHostClientParamsMatchedId(int64_t mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockGetFormRecordParams(bool mockRet);
extern void MockGetFormRecordParamsUid(bool mockRet);
extern void MockGetFormRecordParamsSysUid(bool mockRet);
extern void MockConnectServiceAbility(bool mockRet);
extern void MockGetIntervalTimer(bool mockRet);
extern void MockGetUpdateAtTimer(bool mockRet);
extern void MockGetDynamicItem(bool mockRet);
extern void MockAllotFormHostRecord(bool mockRet);
extern void MockGetCallerBundleName(bool mockRet);
extern void MockGetRequestPublishFormInfo(bool mockRet);
extern void MockGetRequestPublishFormInfoWant(OHOS::AAFwk::Want mockWant);
extern void MockGetAbilityInfo(bool mockRet);
extern void MockGetAbilityInfoByAction(bool mockRet);
extern void MockGetFormsInfoByModule(bool mockRet);
extern void MockGetFormsInfoByModuleParam(bool mockRet);
extern void MockCheckTempEnoughForm(bool mockRet);
extern void MockUpdateDBRecord(bool mockRet);
extern void MockGetFormRecord(bool mockRet);
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
extern void MockGenerateFormId(bool mockRet);
extern void MockGetCallingUid(int32_t mockRet);
void MockRequestPublishFormToHost(bool mockRet);
void MockCheckBundlePermission(bool mockRet);
void MockIsCaller(bool mockRet);

namespace {
constexpr int32_t DEFAULT_CALLING_UID = 20000001;

class FmsFormMgrAdapterTest2 : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FmsFormMgrAdapterTest2::SetUp()
{}

void FmsFormMgrAdapterTest2::TearDown()
{}

/**
 * @tc.name: FormMgrAdapter_0121
 * @tc.desc: test RequestForm function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0121, TestSize.Level0)
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, formMgrAdapter.RequestForm(formId, callerToken, want));
    MockGetMatchedHostClientParamsMatchedId(0);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0121 end";
}

/**
 * @tc.name: FormMgrAdapter_0122
 * @tc.desc: test FormMgrAdapter_0122 function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0122, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0123, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0124, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0125, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0126, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0127, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0128, TestSize.Level0)
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
 * @tc.name: FormMgrAdapter_0128_1
 * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
 HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0128_1, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0128_1 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockDeleteTempForm(true);
     formMgrAdapter.HandleDeleteTempForm(formId, callerToken);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0128_1 end";
 }
 
 /**
  * @tc.name: FormMgrAdapter_0128_2
  * @tc.desc: test HandleDeleteTempForm function and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
  * @tc.type: FUNC
  */
 HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0128_2, TestSize.Level0)
 {
     GTEST_LOG_(INFO) << "FormMgrAdapter_0128_2 start";
     FormMgrAdapter formMgrAdapter;
     int64_t formId = 1;
     sptr<IRemoteObject> callerToken = nullptr;
     MockGetFormRecord(true);
     MockGetFormRecordParams(true);
     MockDeleteTempForm(false);
     formMgrAdapter.HandleDeleteTempForm(formId, callerToken);
     GTEST_LOG_(INFO) << "FormMgrAdapter_0128_2 end";
 }

/**
 * @tc.name: FormMgrAdapter_0129
 * @tc.desc: test CastTempForm function and the return value is ERR_APPEXECFWK_FORM_NOT_EXIST_ID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0129, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0130, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0131, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0132, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0133, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0134, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0135, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0136, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0137, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0138, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0139, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0140, TestSize.Level0)
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
    MockGetFormRecordParamsUid(false);
    MockGetCallingUid(DEFAULT_CALLING_UID);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_NOT_EXIST_ID, formMgrAdapter.AllotFormById(info, callerToken, wantParams, formInfo));
    GTEST_LOG_(INFO) << "FormMgrAdapter_0140 end";
}

/**
 * @tc.name: FormMgrAdapter_0141
 * @tc.desc: test AddNewFormRecord function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0141, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0142, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0143, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0144, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0145, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0146, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0147, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0148, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    FormInfo formInfo = {};
    want.SetElementName("bundleName", "abilityName");
    MockCheckBundlePermission(false);
    MockIsCaller(false);
    std::string str = "aa";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE, formMgrAdapter.GetFormInfo(want, formInfo));
    MockCheckBundlePermission(true);
    MockIsCaller(true);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0148 end";
}

/**
 * @tc.name: FormMgrAdapter_0149
 * @tc.desc: test GetFormItemInfo function and the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0149, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0150, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0151, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0152, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0153, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0154, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0155, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0156, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 start";
    FormMgrAdapter formMgrAdapter;
    Want want = {};
    MockConnectServiceAbility(false);
    EXPECT_NE(formMgrAdapter.RequestPublishFormToHost(want), ERR_APPEXECFWK_FORM_GET_HOST_FAILED);
    GTEST_LOG_(INFO) << "FormMgrAdapter_0156 end";
}

/**
 * @tc.name: FormMgrAdapter_0157
 * @tc.desc: test CheckAddRequestPublishForm function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0157, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0158, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0159, TestSize.Level0)
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
 * @tc.name: FormMgrAdapter_0162
 * @tc.desc: test NotifyFormsVisible function and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0162, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0163, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0164, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0165, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0166, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0167, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0168, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0169, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0170, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0171, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0172, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0173, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0174, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0175, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0176, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0177, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0178, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0179, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0180, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0181, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0182, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0183, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0184, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0185, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0186, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0186 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityOnlyUIAbility_ = ERR_INVALID_VALUE;
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0187, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0187 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    
    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityOnlyUIAbility_ = ERR_INVALID_VALUE;
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0188, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_0188 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> bmsHelperBackup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;

    auto amsHelperBackup = FormAmsHelper::GetInstance().GetAbilityManager();
    auto mockAmsMgr = new (std::nothrow) MockAbilityMgrService();
    mockAmsMgr->startAbilityOnlyUIAbility_ = ERR_OK;
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
 * @tc.name: FormMgrAdapter_0190
 * @tc.desc: test DeleteInvalidForms function and the return value is ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0190, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_192, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_193, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_194, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_0195, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_196, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_197, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_198, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_199, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_200, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_201, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_202, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_203, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_204, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_205, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_206, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_207, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_208, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_209, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_210, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_211, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_211 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(false);
    EXPECT_EQ(false, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    GTEST_LOG_(INFO) << "FormMgrAdapter_211 end";
}

/**
 * @tc.name: FormMgrAdapter_212
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_212, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_212 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t updateDuration = 1;
    MockGetFormRecord(true);
    MockGetFormRecordParams(true);
    EXPECT_EQ(false, formMgrAdapter.GetValidFormUpdateDuration(formId, updateDuration));
    GTEST_LOG_(INFO) << "FormMgrAdapter_212 end";
}

/**
 * @tc.name: FormMgrAdapter_213
 * @tc.desc: test GetValidFormUpdateDuration function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_213, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_214, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_215, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_216, TestSize.Level1)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_217, TestSize.Level2)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_218, TestSize.Level2)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_219, TestSize.Level1)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_220, TestSize.Level2)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_221, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_222, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_223, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_224, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_225, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_226, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_227, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_227 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(formMgrAdapter.SetPublishFormResult(formId, result), ERR_APPEXECFWK_FORM_COMMON_CODE);

    formMgrAdapter.serialQueue_ = std::make_unique<FormSerialQueue>("FormMgrTimerTaskQueueTest");
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_228, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_229, TestSize.Level0)
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
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_230, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_230 start";
    FormMgrAdapter formMgrAdapter;
    formMgrAdapter.SetTimerTaskNeeded(true);
    GTEST_LOG_(INFO) << "FormMgrAdapter_230 end";
}

/**
 * @tc.name: FormMgrAdapter_231
 * @tc.desc: test IsValidPublishEvent function and the return value is true when needCheckFormPermission is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_231, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_231 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    std::string bundleName = "com.ohos.launcher";
    bool needCheckFormPermission = false;
    EXPECT_EQ(true, formMgrAdapter.IsValidPublishEvent(bmsProxy, bundleName, want, needCheckFormPermission));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_231 end";
}

/**
 * @tc.name: FormMgrAdapter_232
 * @tc.desc: test RequestPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_232, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_232 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    bool withFormBindingData = false;
    int64_t formId1 = 1;
    std::unique_ptr<FormProviderData> formBindingData = std::make_unique<FormProviderData>();
    std::vector<FormDataProxy> formDataProxies;

    MockRequestPublishFormToHost(false);
    auto ret = formMgrAdapter.RequestPublishForm(want, withFormBindingData, formBindingData, formId1, formDataProxies);
    MockRequestPublishFormToHost(true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrAdapter_232 end";
}

/**
 * @tc.name: FormMgrAdapter_233
 * @tc.desc: test BatchRefreshForms function and the return value is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_233, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_233 start";
    FormMgrAdapter formMgrAdapter;
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(ERR_OK, formMgrAdapter.BatchRefreshForms(formRefreshType));
    GTEST_LOG_(INFO) << "FormMgrAdapter_233 end";
}

/**
 * @tc.name: FormMgrAdapter_234
 * @tc.desc: test RequestPublishForm function and the return value is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_234, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_234 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    std::string str1 = "aa";
    std::string str2 = "bb";
    std::string str4 = "mm";
    std::string str5 = "xx";
    std::string str6 = "cc";
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str1);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, str2);
    want.SetElementName(str5, str6, str4);
    bool withFormBindingData = false;
    int64_t formId1 = 1;
    std::unique_ptr<FormProviderData> formBindingData = std::make_unique<FormProviderData>();
    std::vector<FormDataProxy> formDataProxies;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    int32_t times = 0;
    constexpr int32_t counts = 2;
    auto bmsTaskCheckIsSystemAppByUid = [&times, counts] (const int uid) {
        return !(++times == counts);
    };
    EXPECT_CALL(*bmsProxy, CheckIsSystemAppByUid(_)).Times(2).WillOnce(Invoke(bmsTaskCheckIsSystemAppByUid))
        .WillOnce(Invoke(bmsTaskCheckIsSystemAppByUid));
    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = "name";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetNameForUid(_, _)).WillOnce(Invoke(bmsTaskGetBundleNameForUid));
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));
    int32_t uid = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormJsInfo formInfo1;
    MockGetBoolParam(false);
    formMgrAdapter.AddForm(formId1, want, callerToken, formInfo1);
    FormProviderData formProviderData;
    MockGetFormRecord(false);
    formMgrAdapter.UpdateForm(formId1, uid, formProviderData);
    MockRequestPublishFormToHost(false);
    MockGenerateFormId(false);
    auto ret = formMgrAdapter.RequestPublishForm(want, withFormBindingData, formBindingData, formId1, formDataProxies);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.CheckPublishForm(want));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    MockGenerateFormId(true);
    GTEST_LOG_(INFO) << "FormMgrAdapter_234 end";
}

/**
 * @tc.name: FormMgrAdapter_235
 * @tc.desc: test EnableForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_235, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_235 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "com.ohos.launcher";
    EXPECT_EQ(formMgrAdapter.EnableForms(bundleName, true), ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    EXPECT_EQ(formMgrAdapter.EnableForms(bundleName, false), ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
}

/**
 * @tc.name: FormMgrAdapter_236
 * @tc.desc: test GetBundleName function and the return value is false when needCheckFormPermission is true.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_236, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_236 start";
    FormMgrAdapter formMgrAdapter;
    std::string bundleName = "";
    bool needCheckFormPermission = true;

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = nullptr;

    EXPECT_EQ(false, formMgrAdapter.GetBundleName(bundleName, needCheckFormPermission));

    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = false;
    EXPECT_EQ(false, formMgrAdapter.GetBundleName(bundleName, needCheckFormPermission));

    appInfo.isSystemApp = true;
    EXPECT_EQ(false, formMgrAdapter.GetBundleName(bundleName, needCheckFormPermission));

    bundleName = "com.ohos.launcher";
    EXPECT_EQ(false, formMgrAdapter.GetBundleName(bundleName, needCheckFormPermission));

    needCheckFormPermission = false;
    EXPECT_EQ(true, formMgrAdapter.GetBundleName(bundleName, needCheckFormPermission));

    GTEST_LOG_(INFO) << "FormMgrAdapter_236 end";
}

/**
 * @tc.name: FormMgrAdapter_237
 * @tc.desc: test CheckFormBundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_237, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_237 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    std::string bundleName = "";
    bool needCheckFormPermission = true;

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.CheckFormBundleName(want, bundleName,
                                                                                        needCheckFormPermission));

    appInfo.isSystemApp = true;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrAdapter.CheckFormBundleName(want, bundleName,
                                                                                        needCheckFormPermission));

    needCheckFormPermission = false;
    bundleName = "com.ohos.launcher";
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, std::string());
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.CheckFormBundleName(want, bundleName,
                                                                                    needCheckFormPermission));

    GTEST_LOG_(INFO) << "FormMgrAdapter_237 end";
}

/**
 * @tc.name: FormMgrAdapter_238
 * @tc.desc: test RequestPublishForm function with needCheckFormPermission is false.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_238, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_238 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    bool withFormBindingData = false;
    int64_t formId1 = 1;
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    std::unique_ptr<FormProviderData> formBindingData = std::make_unique<FormProviderData>();
    std::vector<FormDataProxy> formDataProxies;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = true;

    MockRequestPublishFormToHost(false);
    auto ret = formMgrAdapter.RequestPublishForm(want, withFormBindingData, formBindingData, formId1, formDataProxies);
    MockRequestPublishFormToHost(true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    auto bmsTaskGetBundleNameForUid = [] (const int uid, std::string &name) {
        name = "name";
        GTEST_LOG_(INFO) << "FormMgrAdapter_0237 bmsTaskGetBundleNameForUid called";
        return ERR_OK;
    };
    EXPECT_CALL(*bmsProxy, GetNameForUid(_, _)).Times(1).WillOnce(Invoke(bmsTaskGetBundleNameForUid));
    appInfo.isSystemApp = false;
    MockRequestPublishFormToHost(false);
    ret = formMgrAdapter.RequestPublishForm(want, withFormBindingData, formBindingData, formId1, formDataProxies,
                                            false);
    MockRequestPublishFormToHost(true);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormMgrAdapter_238 end";
}

/**
 * @tc.name: FormMgrAdapter_239
 * @tc.desc: test CheckSnapshotWant function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_239, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_239 start";
    FormMgrAdapter formMgrAdapter;
    Want want;
    
    bool ret = formMgrAdapter.CheckSnapshotWant(want);
    EXPECT_EQ(ret, false);
    std::string snapshotinfo = "fwfaf";
    std::string width = "20";
    std::string height = "30";
    std::string screenx = "40";
    std::string screeny = "20";
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY, snapshotinfo);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY, width);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY, height);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY, screenx);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY, screeny);
    ret = formMgrAdapter.CheckSnapshotWant(want);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "FormMgrAdapter_239 end";
}

/**
 * @tc.name: FormMgrAdapter_240
 * @tc.desc: test IncreaseAddFormRequestTimeOutTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_240, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_240 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId1 = 1;
    formMgrAdapter.IncreaseAddFormRequestTimeOutTask(formId1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_240 end";
}

/**
 * @tc.name: FormMgrAdapter_241
 * @tc.desc: test IncreaseAddFormRequestTimeOutTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_241, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_241 start";
    FormMgrAdapter formMgrAdapter;
    formMgrAdapter.Init();
    int64_t formId1 = 1;
    formMgrAdapter.IncreaseAddFormRequestTimeOutTask(formId1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_241 end";
}

/**
 * @tc.name: FormMgrAdapter_242
 * @tc.desc: test CancelAddFormRequestTimeOutTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_242, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_242 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId1 = 1;
    int result = ERR_OK;
    formMgrAdapter.CancelAddFormRequestTimeOutTask(formId1, result);
    GTEST_LOG_(INFO) << "FormMgrAdapter_242 end";
}

/**
 * @tc.name: FormMgrAdapter_243
 * @tc.desc: test CancelAddFormRequestTimeOutTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_243, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_243 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId1 = 1;
    int result = -1;
    formMgrAdapter.CancelAddFormRequestTimeOutTask(formId1, result);
    GTEST_LOG_(INFO) << "FormMgrAdapter_243 end";
}

/**
 * @tc.name: FormMgrAdapter_244
 * @tc.desc: test CheckAddFormTaskTimeoutOrFailed function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_244, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_244 start";
    FormMgrAdapter formMgrAdapter;
    AddFormResultErrorCode formStates;
    int64_t formId1 = 1;
    auto result = formMgrAdapter.CheckAddFormTaskTimeoutOrFailed(formId1, formStates);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrAdapter_244 end";
}

/**
 * @tc.name: FormMgrAdapter_245
 * @tc.desc: test RemoveFormIdMapElement function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest2, FormMgrAdapter_245, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_245 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId1 = 1;
    formMgrAdapter.RemoveFormIdMapElement(formId1);
    GTEST_LOG_(INFO) << "FormMgrAdapter_245 end";
}
}
