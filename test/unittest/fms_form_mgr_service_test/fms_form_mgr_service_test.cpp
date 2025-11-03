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
#include <string>
#include <thread>

#include "access_token.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "data_center/form_data_mgr.h"
#include "common/event/form_event_util.h"
#include "form_mgr/form_mgr_service.h"
#include "tokenid_kit.h"
#include "data_center/form_info/form_info_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "accesstoken_kit.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "ability_info.h"
#include "bundle_mgr_interface.h"
#include "gmock/gmock.h"
#include "mock_ability_manager.h"
#include "mock_form_params.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AAFwk;

extern void MockCheckAcrossLocalAccountsPermission(bool mockRet);
extern void MockIsSACall(bool mockRet);
extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockVerifyCallingPermission(bool mockRet);
extern void MockIsSystemAppByFullTokenID(bool mockRet);
extern void MockGetCurrentAccountIdRet(int32_t userId);
extern void MockGetCallerBundleName(int32_t mockRet);
extern void MockRrequestPublishForm(int32_t mockRet);

namespace {
const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

const int32_t APP_600 = 600;

class FmsFormMgrServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormMgrServiceTest::SetUpTestCase()
{}

void FmsFormMgrServiceTest::TearDownTestCase()
{}

void FmsFormMgrServiceTest::SetUp()
{}

void FmsFormMgrServiceTest::TearDown()
{}

/**
 * @tc.number: FormMgrService_0001
 * @tc.name: test CheckFMSReady function.
 * @tc.desc: Verify that the return value of the CheckFMSReady interface is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0001 start";
    FormMgrService formMgrService;
    formMgrService.state_ = ServiceRunningState::STATE_NOT_START;
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);
 
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    MockGetCurrentAccountIdRet(Constants::ANY_USERID);
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);
 
    MockGetCurrentAccountIdRet(0);
    FormInfoMgr::GetInstance().hasReloadedFormInfosState_ = false;
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);
 
    FormInfoMgr::GetInstance().hasReloadedFormInfosState_ = true;
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0001 end";
}

/**
 * @tc.number: FormMgrService_0002
 * @tc.name: test LifecycleUpdate function.
 * @tc.desc: Verify that the test program executes as expected when the incoming parameter updateType is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0002 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    bool updateType = false;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.LifecycleUpdate(formIds, callerToken, updateType),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.LifecycleUpdate(formIds, callerToken, updateType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0002 end";
}

/**
 * @tc.number: FormMgrService_0003
 * @tc.name: test LifecycleUpdate function.
 * @tc.desc: Verify that the test program executes as expected when the incoming parameter updateType is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0003 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    bool updateType = true;
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.LifecycleUpdate(formIds, callerToken, updateType));
    GTEST_LOG_(INFO) << "FormMgrService_0003 end";
}

/**
 * @tc.number: FormMgrService_0004
 * @tc.name: test AddForm function.
 * @tc.desc: Verify that the AddForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0004 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formInfo;
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.AddForm(formId, want, callerToken, formInfo));
    GTEST_LOG_(INFO) << "FormMgrService_0004 end";
}

/**
 * @tc.number: FormMgrService_0005
 * @tc.name: test DeleteForm function.
 * @tc.desc: Verify that the DeleteForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0005 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.DeleteForm(formId, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0005 end";
}

/**
 * @tc.number: FormMgrService_0006
 * @tc.name: test ReleaseForm function.
 * @tc.desc: Verify that the ReleaseForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0006 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    constexpr bool delCache = false;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.ReleaseForm(formId, callerToken, delCache), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.ReleaseForm(formId, callerToken, delCache), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0006 end";
}

/**
 * @tc.number: FormMgrService_0007
 * @tc.name: test RequestForm function.
 * @tc.desc: Verify that the RequestForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0007 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    const Want want = {};
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.RequestForm(formId, callerToken, want), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.RequestForm(formId, callerToken, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0007 end";
}

/**
 * @tc.number: FormMgrService_0008
 * @tc.name: test NotifyWhetherVisibleForms function.
 * @tc.desc: Verify that the NotifyWhetherVisibleForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0008 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    constexpr int32_t formVisibleType = 1;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0008 end";
}

/**
 * @tc.number: FormMgrService_0009
 * @tc.name: test CastTempForm function.
 * @tc.desc: Verify that the CastTempForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0009 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.CastTempForm(formId, callerToken));

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.CastTempForm(formId, callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.CastTempForm(formId, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0009 end";
}

/**
 * @tc.number: FormMgrService_0010
 * @tc.name: test MessageEvent function.
 * @tc.desc: Verify that the MessageEvent interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0010 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.MessageEvent(formId, want, callerToken), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.MessageEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.MessageEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0010 end";
}

/**
 * @tc.number: FormMgrService_0011
 * @tc.name: test RouterEvent function.
 * @tc.desc: Verify that the RouterEvent interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0011 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.RouterEvent(formId, want, callerToken), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.RouterEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.RouterEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0011 end";
}

/**
 * @tc.number: FormMgrService_0012
 * @tc.name: test Dump function.
 * @tc.desc: Verify that the Dump interface is called normally and the return value is ERR_APPEXECFWK_FORM_COMMON_CODE.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0012 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"-h" };
    int fd = -1;
    constexpr int32_t userId = 0;
    MockGetCurrentAccountIdRet(userId);
    formMgrService.state_ = ServiceRunningState::STATE_NOT_START;
    EXPECT_EQ(formMgrService.Dump(fd, args), ERR_APPEXECFWK_FORM_COMMON_CODE);

    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_EQ(formMgrService.Dump(fd, args), ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "FormMgrService_0012 end";
}

/**
 * @tc.number: FormMgrService_0013
 * @tc.name: test DeleteInvalidForms function.
 * @tc.desc: Verify that the DeleteInvalidForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0013 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 1;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0013 end";
}

/**
 * @tc.number: FormMgrService_0014
 * @tc.name: test AcquireFormState function.
 * @tc.desc: Verify that the AcquireFormState interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0014 start";
    FormMgrService formMgrService;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.AcquireFormState(want, callerToken, stateInfo), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.AcquireFormState(want, callerToken, stateInfo), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0014 end";
}

/**
 * @tc.number: FormMgrService_0015
 * @tc.name: test NotifyFormsVisible function.
 * @tc.desc: Verify that the NotifyFormsVisible interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0015 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isVisible = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0015 end";
}

/**
 * @tc.number: FormMgrService_0016
 * @tc.name: test NotifyFormsPrivacyProtected function.
 * @tc.desc: Verify that the NotifyFormsPrivacyProtected interface is called normally and the return value is
 *           ERR_APPEXECFWK_FORM_COMMON_CODE.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0016 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isProtected = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0016 end";
}

/**
 * @tc.number: FormMgrService_0017
 * @tc.name: test NotifyFormsEnableUpdate function.
 * @tc.desc: Verify that the NotifyFormsEnableUpdate interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0017 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isEnableUpdate = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken), ERR_OK);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0017 end";
}

/**
 * @tc.number: FormMgrService_0018
 * @tc.name: test GetFormsInfo function.
 * @tc.desc: Verify that the GetFormsInfo interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0018 start";
    FormMgrService formMgrService;
    const FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    MockIsSACall(true);

    MockGetCallerBundleName(ERR_OK);
    EXPECT_EQ(formMgrService.GetFormsInfo(filter, formInfos), ERR_OK);

    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.GetFormsInfo(filter, formInfos), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0018 end";
}

/**
 * @tc.number: FormMgrService_0019
 * @tc.name: test GetFormsInfo function.
 * @tc.desc: Verify that the specified parameter "aa" is passed in, the GetFormsInfo interface is called
 *           normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0019 start";
    FormMgrService formMgrService;
    FormInfoFilter filter;
    filter.moduleName = "aa";
    std::vector<FormInfo> formInfos;
    MockGetCallerBundleName(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfo(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0019 end";
}

/**
 * @tc.number: FormMgrService_0020
 * @tc.name: test ShareForm function.
 * @tc.desc: Verify that the ShareForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0020 start";
    FormMgrService formMgrService;
    int64_t formId = 2;
    const std::string deviceId = "aa";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int64_t requestCode = 2;
    MockIsSACall(true);
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken, requestCode), ERR_OK);

    int64_t invalidFormId = 0;
    EXPECT_EQ(formMgrService.ShareForm(invalidFormId, deviceId, callerToken, requestCode),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    const std::string invalidDeviceId = "";
    EXPECT_EQ(formMgrService.ShareForm(formId, invalidDeviceId, callerToken, requestCode),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    int64_t invalidRequestCode = 0;
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken, invalidRequestCode),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken, requestCode),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken, requestCode),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken, requestCode), ERR_OK);

    sptr<IRemoteObject> callerToken1 = nullptr;
    EXPECT_EQ(formMgrService.ShareForm(formId, deviceId, callerToken1, requestCode), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0020 end";
}

/**
 * @tc.number: FormMgrService_0021
 * @tc.name: test ParseOption function.
 * @tc.desc: Verify the specified null parameter list parameter, the ParseOption interface is called
 *           normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0021 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args;
    FormMgrService::DumpKey key = FormMgrService::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(formMgrService.ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0021 end";
}

/**
 * @tc.number: FormMgrService_0022
 * @tc.name: test ParseOption function.
 * @tc.desc: Verify that 3 exception parameter list parameters are specified, the ParseOption
 *           interface is called normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0022 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"args1", u"args2", u"args3"};
    FormMgrService::DumpKey key = FormMgrService::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(formMgrService.ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0022 end";
}

/**
 * @tc.number: FormMgrService_0023
 * @tc.name: test ParseOption function.
 * @tc.desc: Verify that 2 exception parameter list parameters are specified, the ParseOption
 *           interface is called normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0023 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"args1", u"args3"};
    FormMgrService::DumpKey key = FormMgrService::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(formMgrService.ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0023 end";
}

/**
 * @tc.number: FormMgrService_0024
 * @tc.name: test ParseOption function.
 * @tc.desc: Verify that 1 normal parameter list parameters are specified, the ParseOption
 *           interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0024 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"-h"};
    FormMgrService::DumpKey key = FormMgrService::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_TRUE(formMgrService.ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0024 end";
}

/**
 * @tc.number: FormMgrService_0025
 * @tc.name: test ParseOption function.
 * @tc.desc: Verify that 2 normal parameter list parameters are specified, the ParseOption
 *           interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0025 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"-h", u"-s" };
    FormMgrService::DumpKey key = FormMgrService::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_TRUE(formMgrService.ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0025 end";
}

/**
 * @tc.number: FormMgrService_0026
 * @tc.name: test Dump function.
 * @tc.desc: Verify that 3 exception parameter list parameters are specified, the Dump
 *           interface is called normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0026 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"args1", u"args2", u"args3" };
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "FormMgrService_0026 end";
}

/**
 * @tc.number: FormMgrService_0027
 * @tc.name: test Dump function.
 * @tc.desc: Verify that 1 normal parameter list parameters are specified, the Dump
 *           interface is called normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0027 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"-h" };
    std::string result;
    formMgrService.Dump(args, result);
    EXPECT_FALSE(result.empty());
    GTEST_LOG_(INFO) << "FormMgrService_0027 end";
}

/**
 * @tc.number: FormMgrService_0028
 * @tc.name: test CheckCallerIsSystemApp function.
 * @tc.desc: Verify MockIsSACall is verified to be false, that the CheckCallerIsSystemApp interface is called
 *           normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0028 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    EXPECT_TRUE(formMgrService.CheckCallerIsSystemApp());
    GTEST_LOG_(INFO) << "FormMgrService_0028 end";
}

/**
 * @tc.number: FormMgrService_0029
 * @tc.name: test CheckCallerIsSystemApp function.
 * @tc.desc: Verify MockIsSACall is verified to be true, that the CheckCallerIsSystemApp interface is called
 *           normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0029 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    EXPECT_TRUE(formMgrService.CheckCallerIsSystemApp());
    GTEST_LOG_(INFO) << "FormMgrService_0029 end";
}

/**
 * @tc.number: FormMgrService_0030
 * @tc.name: test CheckCallerIsSystemApp function.
 * @tc.desc: Verify MockIsSACall is verified to be true, that the CheckCallerIsSystemApp interface is called
 *           normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0030 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_TRUE(formMgrService.CheckCallerIsSystemApp());
    GTEST_LOG_(INFO) << "FormMgrService_0030 end";
}

/**
 * @tc.number: FormMgrService_0031
 * @tc.name: test CheckCallerIsSystemApp function.
 * @tc.desc: Verify MockIsSACall is verified to be false, that the CheckCallerIsSystemApp interface is called
 *           normally and the return value is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0031 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_FALSE(formMgrService.CheckCallerIsSystemApp());
    GTEST_LOG_(INFO) << "FormMgrService_0031 end";
}

/**
 * @tc.number: FormMgrService_0032
 * @tc.name: test StartAbility function.
 * @tc.desc: FUNC
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0032 start";
    FormMgrService formMgrService;
    const AAFwk::Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(true);
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    GTEST_LOG_(INFO) << "FormMgrService_0032 end";
}

/**
 * @tc.number: FormMgrService_0033
 * @tc.name: test IsRequestPublishFormSupported function.
 * @tc.desc: Verify that the IsRequestPublishFormSupported interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0033 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    EXPECT_TRUE(formMgrService.IsRequestPublishFormSupported());
    GTEST_LOG_(INFO) << "FormMgrService_0033 end";
}

/**
 * @tc.number: FormMgrService_0034
 * @tc.name: test GetFormsInfoByModule function.
 * @tc.desc: Verify that the GetFormsInfoByModule interface is called normally and the return value
 *           is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0034 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::string moduleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    MockCheckAcrossLocalAccountsPermission(true);
    GTEST_LOG_(INFO) << "FormMgrService_0034 end";
}

/**
 * @tc.number: FormMgrService_0035
 * @tc.name: test GetFormsInfoByModule function.
 * @tc.desc: Verify that the GetFormsInfoByModule interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0035 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::string moduleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0035 end";
}

/**
 * @tc.number: FormMgrService_0036
 * @tc.name: test GetFormsInfoByModule function.
 * @tc.desc: Verify that the GetFormsInfoByModule interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0036 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::string moduleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormsInfoByModule(bundleName,
        moduleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0036 end";
}

/**
 * @tc.number: FormMgrService_0037
 * @tc.name: test GetFormsInfoByApp function.
 * @tc.desc: Verify that the GetFormsInfoByApp interface if the caller do not have the across local
 *           accounts permission and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0037 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0037 end";
}

/**
 * @tc.number: FormMgrService_0038
 * @tc.name: test GetFormsInfoByApp function.
 * @tc.desc: Verify that the GetFormsInfoByApp interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0038 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(true);
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0038 end";
}

/**
 * @tc.number: FormMgrService_0039
 * @tc.name: test GetAllFormsInfo function.
 * @tc.desc: Verify that the GetFormsInfoByApp interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0039 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0039 end";
}

/**
 * @tc.number: FormMgrService_0040
 * @tc.name: test GetAllFormsInfo function.
 * @tc.desc: Verify that the GetAllFormsInfo interface if the caller do not have the across local
 *           accounts permission and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0040 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0040 end";
}

/**
 * @tc.number: FormMgrService_0041
 * @tc.name: test GetAllFormsInfo function.
 * @tc.desc: Verify that the GetAllFormsInfo interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0041, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0041 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0041 end";
}

/**
 * @tc.number: FormMgrService_0042
 * @tc.name: test GetAllFormsInfo function.
 * @tc.desc: Verify that the GetAllFormsInfo interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0042, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0042 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetAllFormsInfo(formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0042 end";
}

/**
 * @tc.number: FormMgrService_0043
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0043, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0043 start";
    FormMgrService formMgrService;
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0043 end";
}

/**
 * @tc.number: FormMgrService_0044
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0044, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0044 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0044 end";
}

/**
 * @tc.number: FormMgrService_0045
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface is called but does not have the calling
 *           permission and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0045, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0045 start";
    FormMgrService formMgrService;

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0045 end";
}

/**
 * @tc.number: FormMgrService_0046
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0046, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0046 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0046 end";
}

/**
 * @tc.number: FormMgrService_0047
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface if the caller do not have the across local accounts
 *           permission and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0047, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0047 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockVerifyCallingPermission(true);
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0047 end";
}

/**
 * @tc.number: FormMgrService_0050
 * @tc.name: test CheckFormPermission function.
 * @tc.desc: Verify that the CheckFormPermission interface if the caller do not have the across local
 *           accounts permission and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0050, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0050 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0050 end";
}

/**
 * @tc.number: FormMgrService_0051
 * @tc.name: test AcquireFormData function.
 * @tc.desc: Verify that the AcquireFormData interface is called normally and
 * the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0051, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0051 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int64_t requestCode = 1;
    MockIsSACall(true);
    MockCheckInvalidForm(ERR_OK);
    AAFwk::WantParams formData;
    EXPECT_EQ(formMgrService.AcquireFormData(formId, requestCode, callerToken, formData),
              ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    int64_t invalidFormId = 0;
    EXPECT_EQ(formMgrService.AcquireFormData(invalidFormId, requestCode, callerToken, formData),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    EXPECT_EQ(formMgrService.AcquireFormData(formId, requestCode, nullptr, formData),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    int64_t invalidRequestCode = 0;
    EXPECT_EQ(formMgrService.AcquireFormData(formId, invalidRequestCode, callerToken, formData),
              ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockIsSACall(false);
    EXPECT_EQ(formMgrService.AcquireFormData(formId, requestCode, callerToken, formData),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    MockIsSACall(true);
    GTEST_LOG_(INFO) << "FormMgrService_0051 end";
}

/**
 * @tc.number: FormMgrService_0052
 * @tc.name: test HiDumpTemporaryFormInfos function.
 * @tc.desc: Verify that the HiDumpTemporaryFormInfos interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0052, TestSize.Level1)
{
    // Add temp formRecords to FormDataMgr
    FormDataMgr::GetInstance().formRecords_.clear();
    FormRecord formRecord;
    formRecord.formTempFlag = true;
    FormDataMgr::GetInstance().formRecords_.emplace(0, formRecord);
    // HiDumpTemporaryFormInfos
    FormMgrService formMgrService;
    std::string args;
    std::string formInfo;
    formMgrService.HiDumpTemporaryFormInfos(args, formInfo);
    EXPECT_EQ(false, formInfo.empty());

    GTEST_LOG_(INFO) << "FormMgrService_0052 end";
}

/**
 * @tc.number: FormMgrService_0053
 * @tc.name: test HiDumpStaticBundleFormInfos function.
 * @tc.desc: Verify that the HiDumpStaticBundleFormInfos interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0053, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0053 start";
    FormMgrService formMgrService;
    std::string args;
    std::string formInfo;
    formMgrService.HiDumpStaticBundleFormInfos(args, formInfo);
    EXPECT_EQ(false, formInfo.empty());

    GTEST_LOG_(INFO) << "FormMgrService_0053 end";
}

/**
 * @tc.number: FormMgrService_0054
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify that the AcquireFormData interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0054, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0054 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken), ERR_OK);

    MockIsSACall(false);
    MockCheckAcrossLocalAccountsPermission(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0054 end";
}

/**
 * @tc.number: FormMgrService_0055
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify that the RegisterFormAddObserverByBundle interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0055, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0055 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0055 end";
}

/**
 * @tc.number: FormMgrService_0056
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify that the RegisterFormAddObserverByBundle interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0056, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0056 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockVerifyCallingPermission(false);
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    MockVerifyCallingPermission(true);
    GTEST_LOG_(INFO) << "FormMgrService_0056 end";
}

/**
 * @tc.number: FormMgrService_0057
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify that the AcquireFormData interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0057, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0057 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.RegisterFormRemoveObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0057 end";
}

/**
 * @tc.number: FormMgrService_0058
 * @tc.name: test RegisterFormRemoveObserverByBundle function.
 * @tc.desc: Verify that the RegisterFormRemoveObserverByBundle interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0058, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0058 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.RegisterFormRemoveObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0058 end";
}

/**
 * @tc.number: FormMgrService_0059
 * @tc.name: test RegisterFormRemoveObserverByBundle function.
 * @tc.desc: Verify that the RegisterFormRemoveObserverByBundle interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0059, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0059 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY,
        formMgrService.RegisterFormRemoveObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0059 end";
}

/**
 * @tc.number: FormMgrService_0060
 * @tc.name: test ReadFormConfigXML function.
 * @tc.desc: Verify that the ReadFormConfigXML interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0060, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0060 start";
    FormMgrService formMgrService;
    EXPECT_EQ(ERR_OK, formMgrService.ReadFormConfigXML());
    GTEST_LOG_(INFO) << "FormMgrService_0060 end";
}

/**
 * @tc.number: FormMgrService_0061
 * @tc.name: test StopRenderingForm function.
 * @tc.desc: Verify that the StopRenderingForm interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0061, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0061 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string compId = "comId";
    int ret = formMgrService.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    ret = formMgrService.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockCheckInvalidForm(ERR_OK);
    ret = formMgrService.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0061 end";
}

/**
 * @tc.number: FormMgrService_0063
 * @tc.name: test SetNextRefreshTime function.
 * @tc.desc: Verify that the SetNextRefreshTime interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0063, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0063 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    int64_t nextTime = 1;
    int ret = formMgrService.SetNextRefreshTime(formId, nextTime);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0063 end";
}

/**
 * @tc.number: FormMgrService_0064
 * @tc.name: test ReleaseRenderer function.
 * @tc.desc: Verify that the ReleaseRenderer interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0064, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0064 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string compId = "comId";
    MockIsSACall(false);
    int ret = formMgrService.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    MockIsSACall(true);
    ret = formMgrService.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0064 end";
}

/**
 * @tc.number: FormMgrService_0065
 * @tc.name: test RequestPublishForm function.
 * @tc.desc: Verify that the RequestPublishForm interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0065, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0065 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    MockVerifyCallingPermission(true);
    MockIsSACall(true);
    MockCheckAcrossLocalAccountsPermission(true);
    MockRrequestPublishForm(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    ErrCode ret = formMgrService.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    want.SetParam(Constants::IS_FORM_AGENT, true);
    MockIsSACall(false);
    MockVerifyCallingPermission(false);
    ret = formMgrService.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    MockCheckAcrossLocalAccountsPermission(false);
    GTEST_LOG_(INFO) << "FormMgrService_0065 end";
}

/**
 * @tc.number: FormMgrService_0066
 * @tc.name: test DumpStorageFormInfos function.
 * @tc.desc: Verify that the DumpStorageFormInfos interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0066, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0066 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    int ret = formMgrService.DumpStorageFormInfos(formInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.DumpStorageFormInfos(formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0066 end";
}

/**
 * @tc.number: FormMgrService_0067
 * @tc.name: test DumpFormInfoByBundleName function.
 * @tc.desc: Verify that the DumpFormInfoByBundleName interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0067 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    std::string bundleName = "bundleName";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    int ret = formMgrService.DumpFormInfoByBundleName(bundleName, formInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.DumpFormInfoByBundleName(bundleName, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0067 end";
}

/**
 * @tc.number: FormMgrService_0068
 * @tc.name: test DumpFormInfoByFormId function.
 * @tc.desc: Verify that the DumpFormInfoByFormId interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0068, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0068 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    std::int64_t formId = 1;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    int ret = formMgrService.DumpFormInfoByFormId(formId, formInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.DumpFormInfoByFormId(formId, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0068 end";
}

/**
 * @tc.number: FormMgrService_0069
 * @tc.name: test OnStop function.
 * @tc.desc: Verify that the OnStop interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0069, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0069 start";
    FormMgrService formMgrService;
    formMgrService.OnStop();
    GTEST_LOG_(INFO) << "FormMgrService_0069 end";
}

/**
 * @tc.number: FormMgrService_0070
 * @tc.name: test HiDumpHelp function.
 * @tc.desc: Verify that the HiDumpHelp interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0070, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0070 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    formMgrService.HiDumpHelp(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0070 end";
}

/**
 * @tc.number: FormMgrService_0071
 * @tc.name: test HiDumpFormInfoByBundleName function.
 * @tc.desc: Verify that the HiDumpFormInfoByBundleName interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0071, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0071 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    formMgrService.HiDumpFormInfoByBundleName(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0071 end";
}

/**
 * @tc.number: FormMgrService_0072
 * @tc.name: test CheckAcrossLocalAccountsPermission function.
 * @tc.desc: Verify that the CheckAcrossLocalAccountsPermission interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0072, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0072 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    bool ret = formMgrService.CheckAcrossLocalAccountsPermission();
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormMgrService_0072 end";
}

/**
 * @tc.number: FormMgrService_0073
 * @tc.name: test CheckAcrossLocalAccountsPermission function.
 * @tc.desc: Verify that the CheckAcrossLocalAccountsPermission interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0073, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0073 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    bool ret = formMgrService.CheckAcrossLocalAccountsPermission();
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "FormMgrService_0073 end";
}

/**
 * @tc.number: FormMgrService_0074
 * @tc.name: test GetRunningFormInfos function.
 * @tc.desc: Verify that the GetRunningFormInfos interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0074, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0074 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0074 end";
}

/**
 * @tc.number: FormMgrService_0075
 * @tc.name: test GetRunningFormInfosByBundleName function.
 * @tc.desc: Verify that the GetRunningFormInfosByBundleName interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0075, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0075 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0075 end";
}

/**
 * @tc.number: FormMgrService_0076
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0076, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0076 start";
    FormMgrService formMgrService;
    const FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0076 end";
}

/**
 * @tc.number: FormMgrService_0077
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0077, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0077 start";
    FormMgrService formMgrService;
    FormInstance formInstance;
    int64_t formId = 1;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    GTEST_LOG_(INFO) << "FormMgrService_0077 end";
}

/**
 * @tc.number: FormMgrService_0078
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0078, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0078 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormInstance formInstance;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0078 end";
}

/**
 * @tc.number: FormMgrService_0079
 * @tc.name: test RegisterAddObserver function.
 * @tc.desc: Verify that the RegisterAddObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0079, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0079 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0079 end";
}

/**
 * @tc.number: FormMgrService_0080
 * @tc.name: test RegisterRemoveObserver function.
 * @tc.desc: Verify that the RegisterRemoveObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0080, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0080 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0080 end";
}
// Please add to file fms_form_mgr_service_test2.cpp
}
