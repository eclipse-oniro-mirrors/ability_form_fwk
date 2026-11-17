/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <unistd.h>

#include "access_token.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "data_center/form_data_mgr.h"
#include "common/event/form_event_util.h"
#include "form_mgr/form_mgr_service.h"
#include "form_mgr/form_mgr_dump_handler.h"
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
#include "inner/mock_form_bms_helper.h"
#include "inner/mock_form_mgr_adapter_facade.h"
#include "inner/mock_form_util.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AAFwk;

extern void MockCheckAcrossLocalAccountsPermission(bool mockRet);
extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockVerifyCallingPermission(bool mockRet);
extern void MockIsSystemAppByFullTokenID(bool mockRet);
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
    // SA branch takes GetCurrentAccountId, so the mock below controls userId.
    MockIsSACall(true);
    formMgrService.state_ = ServiceRunningState::STATE_NOT_START;
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);
 
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    MockGetCurrentAccountIdRet(Constants::ANY_USERID);
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);
 
    MockGetCurrentAccountIdRet(0);
    FormInfoMgr::GetInstance().reloadUserIds_.erase(0);
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_APPEXECFWK_FORM_COMMON_CODE);

    FormInfoMgr::GetInstance().reloadUserIds_.insert(0);
    EXPECT_EQ(formMgrService.CheckFMSReady(), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0001 end";
}

/**
 * @tc.number: FormMgrService_0002
 * @tc.name: test LifecycleUpdate function.
 * @tc.desc: Verify LifecycleUpdate delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK when updateType is false.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0002 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    bool updateType = false;
    // Service-layer permission check was removed; call reaches DisableUpdateForm facade stub.
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
 * @tc.desc: Verify ReleaseForm delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0006 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    constexpr bool delCache = false;
    EXPECT_EQ(formMgrService.ReleaseForm(formId, callerToken, delCache), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0006 end";
}

/**
 * @tc.number: FormMgrService_0007
 * @tc.name: test RequestForm function.
 * @tc.desc: Verify RequestForm delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0007 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    const Want want = {};
    EXPECT_EQ(formMgrService.RequestForm(formId, callerToken, want), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0007 end";
}

/**
 * @tc.number: FormMgrService_0008
 * @tc.name: test NotifyWhetherVisibleForms function.
 * @tc.desc: Verify NotifyWhetherVisibleForms delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0008 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    constexpr int32_t formVisibleType = 1;
    EXPECT_EQ(formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0008 end";
}

/**
 * @tc.number: FormMgrService_0009
 * @tc.name: test CastTempForm function.
 * @tc.desc: Verify CastTempForm reaches CheckInvalidForm and the adapter facade; no service-layer
 *           permission check. CheckInvalidForm return is propagated.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0009 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.CastTempForm(formId, callerToken));

    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.CastTempForm(formId, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0009 end";
}

/**
 * @tc.number: FormMgrService_0010
 * @tc.name: test MessageEvent function.
 * @tc.desc: Verify MessageEvent reaches CheckInvalidForm and the adapter facade; no service-layer
 *           permission check. CheckInvalidForm return is propagated.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0010 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.MessageEvent(formId, want, callerToken), ERR_OK);

    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.MessageEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0010 end";
}

/**
 * @tc.number: FormMgrService_0011
 * @tc.name: test RouterEvent function.
 * @tc.desc: Verify RouterEvent reaches CheckInvalidForm and the adapter facade; no service-layer
 *           permission check. CheckInvalidForm return is propagated.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0011 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(formMgrService.RouterEvent(formId, want, callerToken), ERR_OK);

    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(formMgrService.RouterEvent(formId, want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0011 end";
}

/**
 * @tc.number: FormMgrService_0012
 * @tc.name: test Dump function.
 * @tc.desc: Verify Dump delegates to FormMgrDumpHandler (no state gate at service level);
 *           non-system caller triggers "permission denied" text written to the fd and ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0012 start";
    FormMgrService formMgrService;
    const std::vector<std::u16string> args = { u"-h" };
    constexpr int32_t userId = 0;
    MockGetCurrentAccountIdRet(userId);
    // Non-system caller forces the DumpHandler into its permission-denied branch.
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);

    // Anonymous pipe provides the fd without depending on any device path.
    int fds[2];
    ASSERT_EQ(0, pipe(fds)) << "pipe failed";

    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    EXPECT_EQ(formMgrService.Dump(fds[1], args), ERR_OK);
    close(fds[1]); // send EOF so read() returns 0 after draining

    // Read back and verify the permission-denied text was written.
    char buf[256] = {};
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    ASSERT_GT(n, 0);
    std::string content(buf, static_cast<size_t>(n));
    EXPECT_NE(content.find("permission denied"), std::string::npos);
    GTEST_LOG_(INFO) << "FormMgrService_0012 end";
}

/**
 * @tc.number: FormMgrService_0013
 * @tc.name: test DeleteInvalidForms function.
 * @tc.desc: Verify DeleteInvalidForms delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0013 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 1;
    EXPECT_EQ(formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0013 end";
}

/**
 * @tc.number: FormMgrService_0014
 * @tc.name: test AcquireFormState function.
 * @tc.desc: Verify AcquireFormState delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0014 start";
    FormMgrService formMgrService;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    FormStateInfo stateInfo;
    EXPECT_EQ(formMgrService.AcquireFormState(want, callerToken, stateInfo), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0014 end";
}

/**
 * @tc.number: FormMgrService_0015
 * @tc.name: test NotifyFormsVisible function.
 * @tc.desc: Verify NotifyFormsVisible delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0015 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isVisible = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0015 end";
}

/**
 * @tc.number: FormMgrService_0016
 * @tc.name: test NotifyFormsPrivacyProtected function.
 * @tc.desc: Verify NotifyFormsPrivacyProtected is a no-op stub returning hardcoded
 *           ERR_APPEXECFWK_FORM_COMMON_CODE regardless of caller identity.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0016 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isProtected = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(formMgrService.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken),
              ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrService_0016 end";
}

/**
 * @tc.number: FormMgrService_0017
 * @tc.name: test NotifyFormsEnableUpdate function.
 * @tc.desc: Verify NotifyFormsEnableUpdate delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0017 start";
    FormMgrService formMgrService;
    const std::vector<int64_t> formIds;
    bool isEnableUpdate = false;
    const sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken), ERR_OK);
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
 * @tc.desc: Verify ShareForm validates params (formId, deviceId, callerToken, requestCode)
 *           and CheckInvalidForm; no service-layer permission check.
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
    FormMgrDumpHandler::DumpKey key = FormMgrDumpHandler::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(FormMgrDumpHandler::ParseOption(args, key, value, result));
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
    FormMgrDumpHandler::DumpKey key = FormMgrDumpHandler::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(FormMgrDumpHandler::ParseOption(args, key, value, result));
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
    FormMgrDumpHandler::DumpKey key = FormMgrDumpHandler::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_FALSE(FormMgrDumpHandler::ParseOption(args, key, value, result));
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
    FormMgrDumpHandler::DumpKey key = FormMgrDumpHandler::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_TRUE(FormMgrDumpHandler::ParseOption(args, key, value, result));
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
    FormMgrDumpHandler::DumpKey key = FormMgrDumpHandler::DumpKey::KEY_DUMP_HELP;
    std::string value;
    std::string result;
    EXPECT_TRUE(FormMgrDumpHandler::ParseOption(args, key, value, result));
    GTEST_LOG_(INFO) << "FormMgrService_0025 end";
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
 * @tc.desc: Verify StartAbility rejects empty want (no abilityName and no uri)
 *           with ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY; no service-layer permission check.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0032 start";
    FormMgrService formMgrService;
    const AAFwk::Want want = {};
    const sptr<IRemoteObject> callerToken = nullptr;
    // Empty want triggers local validation; call never reaches AMS.
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);
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
 * @tc.desc: Verify GetFormsInfoByModule delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0034 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::string moduleName;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos), ERR_OK);
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
 * @tc.desc: Verify GetFormsInfoByModule delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK (duplicate of 0034 retained for parity).
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0036 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::string moduleName;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0036 end";
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
    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0038 end";
}

/**
 * @tc.number: FormMgrService_0039
 * @tc.name: test GetFormsInfoByApp function.
 * @tc.desc: Verify GetFormsInfoByApp delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0039 start";
    FormMgrService formMgrService;
    std::string bundleName;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfoByApp(bundleName, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0039 end";
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
 * @tc.desc: Verify GetAllFormsInfo delegates to the adapter facade (no service-layer permission
 *           check); CheckBundlePermission passes with default VerifyCallingPermission mock.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0042, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0042 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formMgrService.GetAllFormsInfo(formInfos));
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

    EXPECT_EQ(formMgrService.AcquireFormData(formId, requestCode, callerToken, formData),
              ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_0051 end";
}

/**
 * @tc.number: FormMgrService_0054
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify RegisterFormAddObserverByBundle delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0054, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0054 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0054 end";
}

/**
 * @tc.number: FormMgrService_0055
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify RegisterFormAddObserverByBundle delegates to the adapter facade (no service-layer
 *           permission check); callerToken non-null reaches SetFormAddObserver and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0055, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0055 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    EXPECT_EQ(ERR_OK, formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0055 end";
}

/**
 * @tc.number: FormMgrService_0056
 * @tc.name: test RegisterFormAddObserverByBundle function.
 * @tc.desc: Verify RegisterFormAddObserverByBundle delegates to the adapter facade (no service-layer
 *           permission check); callerToken non-null reaches SetFormAddObserver and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0056, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0056 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken), ERR_OK);
    EXPECT_EQ(formMgrService.RegisterFormAddObserverByBundle(bundleName, callerToken), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0056 end";
}

/**
 * @tc.number: FormMgrService_0057
 * @tc.name: test RegisterFormRemoveObserverByBundle function.
 * @tc.desc: Verify that the RegisterFormRemoveObserverByBundle interface is called normally and the return value is ERR_OK.
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
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle delegates to the adapter facade (no service-layer
 *           permission check); callerToken non-null reaches SetFormRemoveObserver and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0058, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0058 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    EXPECT_EQ(ERR_OK, formMgrService.RegisterFormRemoveObserverByBundle(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FormMgrService_0058 end";
}

/**
 * @tc.number: FormMgrService_0059
 * @tc.name: test RegisterFormRemoveObserverByBundle function.
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle delegates to the adapter facade (no service-layer
 *           permission check); callerToken non-null reaches SetFormRemoveObserver and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0059, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0059 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "A";
    EXPECT_EQ(ERR_OK, formMgrService.RegisterFormRemoveObserverByBundle(bundleName, callerToken));
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
 * @tc.desc: Verify StopRenderingForm validates formId via CheckInvalidForm and delegates to the
 *           adapter facade. No service-layer permission check. CheckInvalidForm return is propagated.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0061, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0061 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string compId = "comId";
    // Default CheckInvalidForm mock returns ERR_OK, facade StopRenderingForm returns ERR_OK.
    int ret = formMgrService.StopRenderingForm(formId, compId);
    EXPECT_EQ(ret, ERR_OK);

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
 * @tc.desc: Verify ReleaseRenderer delegates to the adapter facade (no service-layer permission
 *           check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0064, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0064 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::string compId = "comId";
    int ret = formMgrService.ReleaseRenderer(formId, compId);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0064 end";
}

/**
 * @tc.number: FormMgrService_0065
 * @tc.name: test RequestPublishForm function.
 * @tc.desc: Verify that RequestPublishForm propagates the adapter facade error and
 *           denies agent publish calls without the required permission.
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
    // system app without the agent permission reaches the VerifyCallingPermission check
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    ret = formMgrService.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    MockCheckAcrossLocalAccountsPermission(false);
    GTEST_LOG_(INFO) << "FormMgrService_0065 end";
}

/**
 * @tc.number: FormMgrService_0066
 * @tc.name: test DumpStorageFormInfos function.
 * @tc.desc: Verify DumpStorageFormInfos delegates to FormMgrDumpHandler (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0066, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0066 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    int ret = formMgrService.DumpStorageFormInfos(formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0066 end";
}

/**
 * @tc.number: FormMgrService_0067
 * @tc.name: test DumpFormInfoByBundleName function.
 * @tc.desc: Verify DumpFormInfoByBundleName delegates to FormMgrDumpHandler (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0067 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    std::string bundleName = "bundleName";
    int ret = formMgrService.DumpFormInfoByBundleName(bundleName, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0067 end";
}

/**
 * @tc.number: FormMgrService_0068
 * @tc.name: test DumpFormInfoByFormId function.
 * @tc.desc: Verify DumpFormInfoByFormId delegates to FormMgrDumpHandler (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0068, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0068 start";
    FormMgrService formMgrService;
    std::string formInfos = "formInfos";
    std::int64_t formId = 1;
    int ret = formMgrService.DumpFormInfoByFormId(formId, formInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0068 end";
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
 * @tc.number: FormMgrService_0074
 * @tc.name: test GetRunningFormInfos function.
 * @tc.desc: Verify GetRunningFormInfos delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0074, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0074 start";
    FormMgrService formMgrService;
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    ErrCode ret = formMgrService.GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0074 end";
}

/**
 * @tc.number: FormMgrService_0075
 * @tc.name: test GetRunningFormInfosByBundleName function.
 * @tc.desc: Verify GetRunningFormInfosByBundleName delegates to the adapter facade
 *           (no service-layer permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0075, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0075 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    ErrCode ret = formMgrService.GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0075 end";
}

/**
 * @tc.number: FormMgrService_0076
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify GetFormInstancesByFilter with empty bundleName filter returns
 *           ERR_APPEXECFWK_FORM_INVALID_PARAM from FormDataMgr parameter validation.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0076, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0076 start";
    FormMgrService formMgrService;
    const FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    ErrCode ret = formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrService_0076 end";
}

/**
 * @tc.number: FormMgrService_0077
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify GetFormInstanceById (2-arg) with no matching form record returns
 *           ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED from FormDataMgr.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0077, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0077 start";
    FormMgrService formMgrService;
    FormInstance formInstance;
    int64_t formId = 1;
    ErrCode ret = formMgrService.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_0077 end";
}

/**
 * @tc.number: FormMgrService_0078
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify GetFormInstanceById (2-arg) with no matching form record returns
 *           ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED from FormDataMgr.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0078, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0078 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormInstance formInstance;
    ErrCode ret = formMgrService.GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0078 end";
}

/**
 * @tc.number: FormMgrService_0079
 * @tc.name: test RegisterAddObserver function.
 * @tc.desc: Verify RegisterAddObserver delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0079, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0079 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    ErrCode ret = formMgrService.RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0079 end";
}

/**
 * @tc.number: FormMgrService_0080
 * @tc.name: test RegisterRemoveObserver function.
 * @tc.desc: Verify RegisterRemoveObserver delegates to the adapter facade (no service-layer
 *           permission check) and returns ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0080, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0080 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    ErrCode ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0080 end";
}

/**
 * @tc.number: UpdateFormCrossBundle_001
 * @tc.name: test UpdateFormCrossBundle delegation when facade returns default.
 * @tc.desc: Verify service delegates to Facade (no service-layer permission check);
 *           facade stub returns default ERR_OK. Permission-deny coverage moved to stub tests.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_001 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormProviderData formProviderData;
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_001 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_002
 * @tc.name: test UpdateFormCrossBundle success path.
 * @tc.desc: Verify ERR_OK is returned when the adapter facade reports success.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_002 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormProviderData formProviderData;
    MockUpdateFormCrossBundle(ERR_OK);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_002 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_003
 * @tc.name: test UpdateFormCrossBundle delegation.
 * @tc.desc: Verify service delegates to Facade (no service-layer permission check);
 *           facade stub returns ERR_OK regardless of caller identity.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_003 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormProviderData formProviderData;
    MockUpdateFormCrossBundle(ERR_OK);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_003 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_004
 * @tc.name: test UpdateFormCrossBundle propagates AdapterFacade errors.
 * @tc.desc: Verify that the Service-layer propagates whatever code AdapterFacade returns.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_004 start";
    FormMgrService formMgrService;
    int64_t formId = -1;
    FormProviderData formProviderData = FormProviderData(std::string("{\"k\":\"v\"}"));
    MockUpdateFormCrossBundle(ERR_APPEXECFWK_FORM_INVALID_PARAM);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_004 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_005
 * @tc.name: test UpdateFormCrossBundle surfaces FORM_NOT_EXIST_ID.
 * @tc.desc: Verify FORM_NOT_EXIST_ID is returned when AdapterFacade reports the form is missing.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_005 start";
    FormMgrService formMgrService;
    int64_t formId = 99999999L;
    FormProviderData formProviderData = FormProviderData(std::string("{\"k\":\"v\"}"));
    MockUpdateFormCrossBundle(ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_005 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_006
 * @tc.name: test UpdateFormCrossBundle transparently propagates arbitrary errors.
 * @tc.desc: Verify that an arbitrary AdapterFacade failure code is passed through unchanged.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_006 start";
    FormMgrService formMgrService;
    int64_t formId = 42;
    FormProviderData formProviderData = FormProviderData(std::string("{\"k\":\"v\"}"));
    MockUpdateFormCrossBundle(ERR_APPEXECFWK_FORM_NOT_TRUST);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_NOT_TRUST);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_006 end";
}
 
/**
 * @tc.number: UpdateFormCrossBundle_008
 * @tc.name: test UpdateFormCrossBundle delegation returns facade default.
 * @tc.desc: Verify service delegates to Facade; facade mock returns ERR_OK.
 *           Permission-deny round-trip coverage moved to stub/dispatch tests.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormCrossBundle_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_008 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    FormProviderData formProviderData = FormProviderData(std::string("{\"k\":\"v\"}"));
    MockUpdateFormCrossBundle(ERR_OK);
    ErrCode ret = formMgrService.UpdateFormCrossBundle(formId, formProviderData);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormCrossBundle_008 end";
}

// ========== UpdateFormsWithReminderAgent Tests ==========

/**
 * @tc.number: UpdateFormsWithReminderAgent_001
 * @tc.name: test UpdateFormsWithReminderAgent delegates regardless of caller identity.
 * @tc.desc: Verify the service delegates to AdapterFacade even for a non-system caller;
 *           permission is enforced by the IPC dispatch layer.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_001 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockUpdateFormsWithReminderAgent(ERR_OK);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("com.test.bundle", 100, Want());
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_001 end";
}

/**
 * @tc.number: UpdateFormsWithReminderAgent_002
 * @tc.name: test UpdateFormsWithReminderAgent forwards empty bundleName to AdapterFacade.
 * @tc.desc: Verify the service performs no bundleName validation; the dispatch-layer
 *           handler rejects an empty bundleName before the service is reached.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_002 start";
    FormMgrService formMgrService;
    MockUpdateFormsWithReminderAgent(ERR_APPEXECFWK_FORM_INVALID_PARAM);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("", 100, Want());
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_002 end";
}

/**
 * @tc.number: UpdateFormsWithReminderAgent_003
 * @tc.name: test UpdateFormsWithReminderAgent forwards negative userId to AdapterFacade.
 * @tc.desc: Verify the service performs no userId validation; the dispatch-layer handler
 *           rejects a negative userId before the service is reached.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_003 start";
    FormMgrService formMgrService;
    MockUpdateFormsWithReminderAgent(ERR_OK);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("com.test.bundle", -1, Want());
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_003 end";
}

/**
 * @tc.number: UpdateFormsWithReminderAgent_004
 * @tc.name: test UpdateFormsWithReminderAgent success path.
 * @tc.desc: Verify ERR_OK is returned when AdapterFacade succeeds and params are valid.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_004 start";
    FormMgrService formMgrService;
    MockUpdateFormsWithReminderAgent(ERR_OK);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("com.test.bundle", 100, Want());
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_004 end";
}

/**
 * @tc.number: UpdateFormsWithReminderAgent_005
 * @tc.name: test UpdateFormsWithReminderAgent propagates AdapterFacade errors.
 * @tc.desc: Verify that the Service-layer propagates whatever code AdapterFacade returns.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_005 start";
    FormMgrService formMgrService;
    MockUpdateFormsWithReminderAgent(ERR_APPEXECFWK_FORM_COMMON_CODE);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("com.test.bundle", 100, Want());
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_005 end";
}

/**
 * @tc.number: UpdateFormsWithReminderAgent_006
 * @tc.name: test UpdateFormsWithReminderAgent delegates regardless of cross-account permission.
 * @tc.desc: Verify the service delegates to AdapterFacade even when across-local-accounts
 *           permission would be denied; the check is enforced by the IPC dispatch layer.
 */
HWTEST_F(FmsFormMgrServiceTest, UpdateFormsWithReminderAgent_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_006 start";
    FormMgrService formMgrService;
    MockIsSACall(false);
    MockCheckAcrossLocalAccountsPermission(false);
    MockUpdateFormsWithReminderAgent(ERR_OK);

    ErrCode ret = formMgrService.UpdateFormsWithReminderAgent("com.test.bundle", 100, Want());
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "UpdateFormsWithReminderAgent_006 end";
}

// Please add to file fms_form_mgr_service_test2.cpp
}
