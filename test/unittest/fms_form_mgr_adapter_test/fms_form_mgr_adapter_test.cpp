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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "form_mgr_adapter.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetBoolParam(bool mockRet);
extern void MockExistTempForm(bool mockRet);
extern void MockGetDBRecord(bool mockRet);
extern void MockExistFormRecord(bool mockRet);
extern void MockGetMatchedHostClient(bool mockRet);
extern void MockGetFormRecord(bool mockRet);
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
    int uid = 1;
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
    int uid = 1;
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
    int uid = 1;
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
    int uid = 1;
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
    std::string bundleName = "";
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UpdateForm(formId, bundleName, formProviderData));
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
    std::string bundleName = "aa";
    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.UpdateForm(formId, bundleName, formProviderData));
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
 * @tc.name: FormMgrAdapter_049
 * @tc.desc: test SetNextRefreshTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrAdapterTest, FormMgrAdapter_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrAdapter_049 start";
    FormMgrAdapter formMgrAdapter;
    int64_t formId = 1;
    int64_t nextTime = 1;
    MockGetCallerBundleName(false);
    MockGetUidByBundleName(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrAdapter.SetNextRefreshTime(formId, nextTime));
    GTEST_LOG_(INFO) << "FormMgrAdapter_049 end";
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
}