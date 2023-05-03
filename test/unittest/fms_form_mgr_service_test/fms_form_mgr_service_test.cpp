/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "form_data_mgr.h"
#include "form_event_util.h"
#include "form_mgr_service.h"
#include "tokenid_kit.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockCheckAcrossLocalAccountsPermission(bool mockRet);
extern void MockIsSACall(bool mockRet);
extern void MockCheckInvalidForm(int32_t mockRet);
extern void MockVerifyCallingPermission(bool mockRet);
extern void MockIsSystemAppByFullTokenID(bool mockRet);
extern void MockGetCurrentAccountIdRet(int32_t userId);
extern void MockGetCallerBundleName(int32_t mockRet);
extern void MockGetTokenTypeFlag(uint32_t mockRet);

namespace {
const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

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
 * @tc.name: test IsReady function.
 * @tc.desc: Verify that the return value of the IsReady interface is true.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0001 start";
    FormMgrService formMgrService;
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    formMgrService.runner_ = EventRunner::Create(NAME_FORM_MGR_SERVICE);
    formMgrService.handler_ = std::make_shared<FormEventHandler>(formMgrService.runner_);
    constexpr int32_t userId = 0;
    MockGetCurrentAccountIdRet(userId);
    EXPECT_TRUE(formMgrService.IsReady());
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
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.LifecycleUpdate(formIds, callerToken, updateType));
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
    EXPECT_EQ(ERR_OK, formMgrService.ReleaseForm(formId, callerToken, delCache));
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
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.RequestForm(formId, callerToken, want));
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
    MockIsSACall(true);
    EXPECT_EQ(ERR_OK, formMgrService.NotifyWhetherVisibleForms(formIds, callerToken, formVisibleType));
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
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.MessageEvent(formId, want, callerToken));
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
    MockCheckInvalidForm(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.RouterEvent(formId, want, callerToken));
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
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    formMgrService.runner_ = EventRunner::Create(NAME_FORM_MGR_SERVICE);
    formMgrService.handler_ = std::make_shared<FormEventHandler>(formMgrService.runner_);
    constexpr int32_t userId = 0;
    MockGetCurrentAccountIdRet(userId);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.Dump(fd, args));
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
    EXPECT_EQ(ERR_OK, formMgrService.DeleteInvalidForms(formIds, callerToken, numFormsDeleted));
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
    EXPECT_EQ(ERR_OK, formMgrService.AcquireFormState(want, callerToken, stateInfo));
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
    EXPECT_EQ(ERR_OK, formMgrService.NotifyFormsVisible(formIds, isVisible, callerToken));
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE,
        formMgrService.NotifyFormsPrivacyProtected(formIds, isProtected, callerToken));
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
    EXPECT_EQ(ERR_OK, formMgrService.NotifyFormsEnableUpdate(formIds, isEnableUpdate, callerToken));
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
    MockGetCallerBundleName(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.GetFormsInfo(filter, formInfos));
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
    EXPECT_EQ(ERR_OK, formMgrService.ShareForm(formId, deviceId, callerToken, requestCode));
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_INFO_FAILED, formMgrService.StartAbility(want, callerToken));
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.GetFormsInfoByModule(bundleName, moduleName, formInfos));
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
 * @tc.number: FormMgrService_0048
 * @tc.name: test UpdateForm function.
 * @tc.desc: Verify that the UpdateForm interface is called normally and the return value
 *           is ERR_APPEXECFWK_FORM_COMMON_CODE.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0048, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0048 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const FormProviderData formProviderData = {};
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formMgrService.UpdateForm(formId, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrService_0048 end";
}

/**
 * @tc.number: FormMgrService_0049
 * @tc.name: test UpdateForm function.
 * @tc.desc: Verify that the UpdateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0049, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0049 start";
    FormMgrService formMgrService;
    constexpr int64_t formId = 1;
    const FormProviderData formProviderData = {};
    MockGetCallerBundleName(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.UpdateForm(formId, formProviderData));
    GTEST_LOG_(INFO) << "FormMgrService_0049 end";
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
 * @tc.desc: Verify that the AcquireFormData interface is called normally and the return value is ERR_APPEXECFWK_FORM_GET_INFO_FAILED.
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_INFO_FAILED, formMgrService.AcquireFormData(formId, requestCode, callerToken, formData));
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
}
