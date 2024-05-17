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
#include "form_data_mgr.h"
#include "form_event_util.h"
#include "form_mgr_service.h"
#include "tokenid_kit.h"
#include "form_info_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "accesstoken_kit.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
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
extern void MockGetTokenTypeFlag(uint32_t mockRet);
extern void MockGetAbilityManager(sptr<AAFwk::IAbilityManager> abilityManager);
#ifdef THEME_MGR_ENABLE
extern void MockSetThemeManagerAddFormResult(int mockRet);
#endif

namespace {
const std::string NAME_FORM_MGR_SERVICE = "FormMgrService";

const int32_t APP_600 = 600;

class MockBundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit MockBundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
    {}
    virtual ~MockBundleMgrProxy()
    {}

    MOCK_METHOD5(QueryAbilityInfo, bool(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &callBack));
    bool QueryAbilityInfo(const AAFwk::Want &want, AbilityInfo &abilityInfo) override
    {
        return true;
    }

    std::string GetAppType(const std::string &bundleName) override
    {
        return "system";
    }

    int GetUidByBundleName(const std::string &bundleName, const int userId) override
    {
        if (bundleName.compare("com.form.host.app600") == 0) {
            return APP_600;
        }
        return 0;
    }

    bool GetBundleNameForUid(const int uid, std::string &bundleName) override
    {
        bundleName = "com.form.service";
        return true;
    }

    int32_t GetNameForUid(const int uid, std::string &bundleName) override
    {
        return GetNameForUid_;
    };

    bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfo) override
    {
        return false;
    };
    bool GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfo) override
    {
        return false;
    };

    ErrCode GetBundlePackInfo(const std::string &bundleName, int32_t flags,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override
    {
        GTEST_LOG_(INFO) << "GetBundlePackInfo int32_t";
        return GetBundlePackInfo_;
    }

    ErrCode GetBundlePackInfo(const std::string &bundleName, const BundlePackFlag flag,
        BundlePackInfo &bundlePackInfo, int32_t userId = Constants::UNSPECIFIED_USERID) override
    {
        GTEST_LOG_(INFO) << "GetBundlePackInfo BundlePackFlag";
        return GetBundlePackInfo_;
    }

    bool SetModuleRemovable(
        const std::string &bundleName, const std::string &moduleName, bool isEnable) override
    {
        return setModuleRemovable_;
    }

    sptr<IBundleInstaller> GetBundleInstaller() override
    {
        return nullptr;
    }

    ErrCode GetBundlePackInfo_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    bool setModuleRemovable_ = false;
    int32_t GetNameForUid_ = ERR_OK;
};

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
    formMgrService.state_ = ServiceRunningState::STATE_RUNNING;
    constexpr int32_t userId = 0;
    MockGetCurrentAccountIdRet(userId);
    FormInfoMgr::GetInstance().hasReloadedFormInfosState_ = true;
    EXPECT_TRUE(formMgrService.CheckFMSReady());
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
    ErrCode ret = formMgrService.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    want.SetParam(Constants::IS_FORM_AGENT, true);
    MockIsSACall(false);
    ret = formMgrService.RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
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

/**
 * @tc.number: FormMgrService_0081
 * @tc.name: test UpdateProxyForm function.
 * @tc.desc: Verify that the UpdateProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0081, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0081 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    const FormProviderData formBindingData;
    const std::vector<FormDataProxy> formDataProxies;
    ErrCode ret = formMgrService.UpdateProxyForm(formId, formBindingData, formDataProxies);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0081 end";
}

/**
 * @tc.number: FormMgrService_0082
 * @tc.name: test RegisterRemoveObserver function.
 * @tc.desc: Verify that the RegisterRemoveObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0082, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0082 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0082 end";
}

/**
 * @tc.number: FormMgrService_0083
 * @tc.name: test RequestPublishProxyForm function.
 * @tc.desc: Verify that the RequestPublishProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0083, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0083 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    const std::vector<FormDataProxy> formDataProxies;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);
    GTEST_LOG_(INFO) << "FormMgrService_0083 end";
}

/**
 * @tc.number: FormMgrService_0084
 * @tc.name: test RequestPublishProxyForm function.
 * @tc.desc: Verify that the RequestPublishProxyForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0084, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0084 start";
    FormMgrService formMgrService;
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    const std::vector<FormDataProxy> formDataProxies;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    ErrCode ret = formMgrService.RequestPublishProxyForm(want, withFormBindingData, formBindingData,
        formId, formDataProxies);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, ret);
    GTEST_LOG_(INFO) << "FormMgrService_0084 end";
}


/**
 * @tc.number: FormMgrService_0085
 * @tc.name: test BackgroundEvent function.
 * @tc.desc: Verify that the BackgroundEvent interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0085, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0085 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    Want want;
    const sptr<IRemoteObject> callerToken = nullptr;
    MockIsSACall(false);
    int ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    MockCheckInvalidForm(ERR_APPEXECFWK_FORM_COMMON_CODE);
    ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockCheckInvalidForm(ERR_OK);
    ret = formMgrService.BackgroundEvent(formId, want, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0085 end";
}

/**
 * @tc.number: FormMgrService_0086
 * @tc.name: test RegisterFormRouterProxy function.
 * @tc.desc: Verify that the RegisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0086, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0086 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    int ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0086 end";
}

/**
 * @tc.number: FormMgrService_0087
 * @tc.name: test UnregisterFormRouterProxy function.
 * @tc.desc: Verify that the UnregisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0087, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0087 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    MockIsSACall(false);
    int ret = formMgrService.UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0087 end";
}

/**
 * @tc.number: FormMgrService_0088
 * @tc.name: test RegisterFormRouterProxy function.
 * @tc.desc: Verify that the RegisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0088, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0088 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();;
    int ret = formMgrService.RegisterFormRouterProxy(formIds, callerToken);
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0088 end";
}

/**
 * @tc.number: FormMgrService_0089
 * @tc.name: test UnregisterFormRouterProxy function.
 * @tc.desc: Verify that the UnregisterFormRouterProxy interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0089, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0089 start";
    FormMgrService formMgrService;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    int ret = formMgrService.UnregisterFormRouterProxy(formIds);
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CheckFormPermission());
    GTEST_LOG_(INFO) << "FormMgrService_0089 end";
}

/**
 * @tc.number: FormMgrService_0090
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_INVALID_PARAM.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0090, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0090 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0090 end";
}

/**
 * @tc.number: FormMgrService_0091
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0091, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0091 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0091 end";
}

/**
 * @tc.number: FormMgrService_0092
 * @tc.name: test GetFormInstancesByFilter function.
 * @tc.desc: Verify that the GetFormInstancesByFilter interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0092, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0092 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    FormMgrService formMgrService;
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY,
        formMgrService.GetFormInstancesByFilter(formInstancesFilter, formInstances));
    GTEST_LOG_(INFO) << "FormMgrService_0092 end";
}

/**
 * @tc.number: FormMgrService_0093
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0093, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0093 start";
    MockIsSACall(true);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0093 end";
}

/**
 * @tc.number: FormMgrService_0094
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0094, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0094 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0094 end";
}

/**
 * @tc.number: FormMgrService_0095
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 * and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0095, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0095 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(false);
    FormMgrService formMgrService;
    int64_t formId = 800;
    FormInstance formInstance;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.GetFormInstanceById(formId, formInstance));
    GTEST_LOG_(INFO) << "FormMgrService_0095 end";
}

/**
 * @tc.number: FormMgrService_0096
 * @tc.name: test HasFormVisible function.
 * @tc.desc: Verify that the HasFormVisible interface is called normally and the return value is right.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0096, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0096 start";
    std::string bundleName = "ohos.samples.FormApplication";
    int32_t userId = 100;
    int32_t instIndex = 0;
    // create formRecords_
    FormRecord record;
    record.bundleName = bundleName;
    record.userId = userId;
    record.formVisibleNotifyState = 1;
    int64_t formId = 123456;
    FormDataMgr::GetInstance().formRecords_.emplace(formId, record);

    // create tokenid
    uint32_t tokenId = 0;
    MockFormParams::bundleName = bundleName;
    MockFormParams::userId = userId;

    MockIsSACall(true);
    FormMgrService formMgrService;
    EXPECT_EQ(true, formMgrService.HasFormVisible(tokenId));

    MockFormParams::Reset();
    EXPECT_EQ(false, formMgrService.HasFormVisible(tokenId));
    GTEST_LOG_(INFO) << "FormMgrService_0096 end";
}

/**
 * @tc.number: FormMgrService_0097
 * @tc.name: test HiDumpHasFormVisible function.
 * @tc.desc: Verify that the HiDumpHasFormVisible interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0097, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0097 start";
    FormMgrService formMgrService;
    std::string args = "args";
    std::string result = "result";
    formMgrService.HiDumpHasFormVisible(args, result);
    GTEST_LOG_(INFO) << "FormMgrService_0097 end";
}

/**
 * @tc.number: FormMgrService_0098
 * @tc.name: test StartAbility function.
 * @tc.desc: Verify that the StartAbility interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0098, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0098 start";
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    FormMgrService formMgrService;
    std::string str = "aa";
    Want want;
    want.SetElementName("", "");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, str);
    const sptr<IRemoteObject> callerToken = nullptr;
    MockGetAbilityManager(new MockAbilityMgrService());
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY);

    want.SetElementName("bundleName", "abilityName");
    MockGetAbilityManager(nullptr);
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockGetAbilityManager(new MockAbilityMgrService());
    EXPECT_EQ(formMgrService.StartAbility(want, callerToken), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0098 end";
}

/**
 * @tc.number: FormMgrService_0099
 * @tc.name: test FormMgr HiDumpFormRunningFormInfos function.
 * @tc.desc: Verify that the HiDumpFormRunningFormInfos interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0099, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0099 start";
    FormMgrService formMgrService;
    std::string args;
    std::string RunningFormInfo;
    formMgrService.HiDumpFormRunningFormInfos(args, RunningFormInfo);
    GTEST_LOG_(INFO) << "FormMgrService_0099 end";
}

/**
 * @tc.number: FormMgrService_0100
 * @tc.name: test GetFormsInfoByFilter function.
 * @tc.desc: Verify that the GetFormsInfoByFilter interface if the caller is not a system app
 *           and the return value is ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0100 start";
    FormMgrService formMgrService;
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, formMgrService.GetFormsInfoByFilter(filter, formInfos));
    GTEST_LOG_(INFO) << "FormMgrService_0100 end";
}

/**
 * @tc.number: FormMgrService_0101
 * @tc.name: test UpdateFormLocation function.
 * @tc.desc: Verify that the UpdateFormLocation interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0101, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0101 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    int32_t formLocation = 1;
    EXPECT_EQ(ERR_OK, formMgrService.UpdateFormLocation(formId, formLocation));
    GTEST_LOG_(INFO) << "FormMgrService_0101 end";
}

/**
 * @tc.number: FormMgrService_0102
 * @tc.name: test RegisterPublishFormInterceptor function.
 * @tc.desc: Verify that the RegisterPublishFormInterceptor interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0102 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = nullptr;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    FormBmsHelper::GetInstance().SetBundleManager(bundleManager);
    EXPECT_EQ(formMgrService.RegisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "FormMgrService_0102 end";
}

/**
 * @tc.number: FormMgrService_0103
 * @tc.name: test UnregisterPublishFormInterceptor function.
 * @tc.desc: Verify that the UnregisterPublishFormInterceptor interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0103 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = nullptr;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    FormBmsHelper::GetInstance().SetBundleManager(bundleManager);
    EXPECT_EQ(formMgrService.UnregisterPublishFormInterceptor(callerToken), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "FormMgrService_0103 end";
}

/**
 * @tc.number: FormMgrService_0104
 * @tc.name: test HiDump functions.
 * @tc.desc: Verify that the HiDump interfaces are calling normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0104 start";
    FormMgrService formMgrService;
    std::string args;
    std::string formInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    formMgrService.HiDumpStorageFormInfos(args, formInfo);
    formMgrService.HiDumpTemporaryFormInfos(args, formInfo);
    formMgrService.HiDumpStaticBundleFormInfos(args, formInfo);
    formMgrService.HiDumpFormInfoByBundleName(args, formInfo);
    formMgrService.HiDumpHasFormVisible(args, formInfo);
    formMgrService.HiDumpFormInfoByFormId(args, formInfo);

    std::string args0 = "0";
    formMgrService.HiDumpFormInfoByFormId(args0, formInfo);
    std::string args1 = "1";
    formMgrService.HiDumpFormInfoByFormId(args1, formInfo);

    GTEST_LOG_(INFO) << "FormMgrService_0104 end";
}

/**
 * @tc.number: FormMgrService_0105
 * @tc.name: test GetCurrentDateTime function.
 * @tc.desc: Verify that the GetCurrentDateTime interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0105, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0105 start";
    FormMgrService formMgrService;
    EXPECT_NE(formMgrService.GetCurrentDateTime(), "");

    GTEST_LOG_(INFO) << "FormMgrService_0105 end";
}

/**
 * @tc.number: FormMgrService_0106
 * @tc.name: test GetCurrentDateTime function.
 * @tc.desc: Verify that the GetCurrentDateTime interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0106 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    Want want;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RecoverForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "FormMgrService_0106 end";
}

/**
 * @tc.number: FormMgrService_0107
 * @tc.name: test GetFormsCount function.
 * @tc.desc: Verify that the GetFormsCount interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0107, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0107 start";
    FormMgrService formMgrService;
    bool isTempFormFlag = true;
    int32_t formCount;
    EXPECT_EQ(formMgrService.GetFormsCount(isTempFormFlag, formCount), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0107 end";
}

/**
 * @tc.number: FormMgrService_0108
 * @tc.name: test GetFormsCount function.
 * @tc.desc: Verify that the GetFormsCount interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0108, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0108 start";
    FormMgrService formMgrService;
    std::string bundleName = "bundleName";
    int32_t formCount;
    EXPECT_EQ(formMgrService.GetHostFormsCount(bundleName, formCount), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0108 end";
}

/**
 * @tc.number: FormMgrService_0109
 * @tc.name: test GetFormInstanceById function.
 * @tc.desc: Verify that the GetFormInstanceById interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0109, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0109 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    FormInstance formInstance;
    bool isUnusedInclude = false;
    MockIsSACall(false);
    ErrCode ret = formMgrService.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.GetFormInstanceById(formId, isUnusedInclude, formInstance);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0109 end";
}

/**
 * @tc.number: FormMgrService_0110
 * @tc.name: test RegisterClickEventObserver function.
 * @tc.desc: Verify that the RegisterClickEventObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0110, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0110 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    const std::string bundleName = "";
    const std::string formEventType = "";

    ErrCode ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RegisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0110 end";
}

/**
 * @tc.number: FormMgrService_0111
 * @tc.name: test UnregisterClickEventObserver function.
 * @tc.desc: Verify that the UnregisterClickEventObserver interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0111, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0111 start";
    FormMgrService formMgrService;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    MockIsSACall(false);
    const std::string bundleName = "";
    const std::string formEventType = "";

    ErrCode ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.UnregisterClickEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0111 end";
}

/**
 * @tc.number: FormMgrService_0112
 * @tc.name: test SetFormsRecyclable function.
 * @tc.desc: Verify that the SetFormsRecyclable interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0112, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0112 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    MockIsSACall(false);
    ErrCode ret = formMgrService.SetFormsRecyclable(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.SetFormsRecyclable(formIds);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrService_0112 end";
}

/**
 * @tc.number: FormMgrService_0113
 * @tc.name: test RecycleForms function.
 * @tc.desc: Verify that the RecycleForms interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0113, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0113 start";
    FormMgrService formMgrService;
    std::vector<int64_t> formIds;
    Want want;
    MockIsSACall(false);
    ErrCode ret = formMgrService.RecycleForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    ret = formMgrService.RecycleForms(formIds, want);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrService_0113 end";
}


/**
 * @tc.number: FormMgrService_0114
 * @tc.name: test updateForm function.
 * @tc.desc: Verify that the UpdateForm interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0114, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0114 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    FormProviderData formProviderData;
    EXPECT_EQ(formMgrService.UpdateForm(formId, formProviderData), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0114 end";
}

/**
 * @tc.number: FormMgrService_0115
 * @tc.name: test DumpFormTimerByFormId function.
 * @tc.desc: Verify that the DumpFormTimerByFormId interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0115, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0115 start";
    FormMgrService formMgrService;
    const int64_t formId = 1;
    std::string isTimingService;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.DumpFormTimerByFormId(formId, isTimingService), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.DumpFormTimerByFormId(formId, isTimingService), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0115 end";
}

/**
 * @tc.number: FormMgrService_0116
 * @tc.name: test RecvFormShareInfoFromRemote function.
 * @tc.desc: Verify that the RecvFormShareInfoFromRemote interface is called normally
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0116, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0116 start";
    FormMgrService formMgrService;
    FormShareInfo formShareInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    EXPECT_EQ(formMgrService.RecvFormShareInfoFromRemote(formShareInfo), ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    MockIsSACall(true);
    EXPECT_EQ(formMgrService.RecvFormShareInfoFromRemote(formShareInfo), ERR_OK);

    GTEST_LOG_(INFO) << "FormMgrService_0116 end";
}

/**
 * @tc.number: FormMgrService_0117
 * @tc.name: test CreateForm function.
 * @tc.desc: Verify that the CreateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0117, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0117 start";
    FormMgrService formMgrService;
    Want want;
    RunningFormInfo runningFormInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY, formMgrService.CreateForm(want, runningFormInfo));

    MockCheckAcrossLocalAccountsPermission(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formMgrService.CreateForm(want, runningFormInfo));
    GTEST_LOG_(INFO) << "FormMgrService_0117 end";
}

/**
 * @tc.number: FormMgrService_0118
 * @tc.name: test CreateForm function.
 * @tc.desc: Verify that the CreateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0118, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0118 start";
    FormMgrService formMgrService;
    Want want;
    want.SetParam(AppExecFwk::Constants::PARAM_THEME_KEY, true);
    RunningFormInfo runningFormInfo;
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockCheckAcrossLocalAccountsPermission(true);
#ifdef THEME_MGR_ENABLE
    GTEST_LOG_(INFO) << "FormMgrService_0118 THEME_MGR_ENABLE defined";
    MockSetThemeManagerAddFormResult(ERR_OK);
    EXPECT_EQ(ERR_OK, formMgrService.CreateForm(want, runningFormInfo));
#else
    GTEST_LOG_(INFO) << "FormMgrService_0118 THEME_MGR_ENABLE undefined";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED, formMgrService.CreateForm(want, runningFormInfo));
#endif

    GTEST_LOG_(INFO) << "FormMgrService_0118 end";
}

/**
 * @tc.number: FormMgrService_0119
 * @tc.name: test FormMgr HiDumpFormBlockedApps function.
 * @tc.desc: Verify that the HiDumpFormBlockedApps interface is available.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0119, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0119 start";
    FormMgrService formMgrService;
    std::string args;
    std::string blockAppInfo;
    formMgrService.HiDumpFormBlockedApps(args, blockAppInfo);
    GTEST_LOG_(INFO) << "FormMgrService_0119 end";
}

/**
 * @tc.number: FormMgrService_0120
 * @tc.name: test SetPublishFormResult function.
 * @tc.desc: Verify that the SetPublishFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0120, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0120 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(formMgrService.SetPublishFormResult(formId, result), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0120 end";
}

/**
 * @tc.number: FormMgrService_0121
 * @tc.name: test AcquireAddFormResult function.
 * @tc.desc: Verify that the AcquireAddFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0121, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0121 start";
    MockIsSACall(true);
    FormMgrService formMgrService;
    int64_t formId = 1;
    EXPECT_EQ(formMgrService.AcquireAddFormResult(formId), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrService_0121 end";
}

/**
 * @tc.number: FormMgrService_0122
 * @tc.name: test OnSystemloadLevel function.
 * @tc.desc: Verify that the OnSystemloadLevel interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0122, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0122 start";
    FormMgrService formMgrService;
    int32_t level = 5;
    formMgrService.OnSystemloadLevel(level);
    GTEST_LOG_(INFO) << "FormMgrService_0122 end";
}

/**
 * @tc.number: FormMgrService_0123
 * @tc.name: test OnSystemloadLevel function.
 * @tc.desc: Verify that the OnSystemloadLevel interface is called normally.
 */
HWTEST_F(FmsFormMgrServiceTest, FormMgrService_0123, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrService_0123 start";
    FormMgrService formMgrService;
    int32_t level = 1;
    formMgrService.OnSystemloadLevel(level);
    GTEST_LOG_(INFO) << "FormMgrService_0123 end";
}
}
