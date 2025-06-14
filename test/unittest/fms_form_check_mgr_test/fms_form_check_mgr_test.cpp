/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>
#define private public
#include "form_refresh/check_mgr/system_app_checker.h"
#include "form_refresh/check_mgr/self_form_checker.h"
#include "form_refresh/check_mgr/calling_user_checker.h"
#include "form_refresh/check_mgr/calling_bundle_checker.h"
#include "form_refresh/check_mgr/active_user_checker.h"
#include "form_refresh/check_mgr/add_finish_checker.h"
#include "form_refresh/refresh_impl/form_data_refresh_impl.h"
#include "form_refresh/refresh_impl/form_force_refresh_impl.h"
#include "form_refresh/refresh_impl/form_host_refresh_impl.h"
#include "form_refresh/refresh_impl/form_net_conn_refresh_impl.h"
#include "form_refresh/refresh_impl/form_next_time_refresh_impl.h"
#include "form_refresh/refresh_impl/form_refresh_after_uncontrol_impl.h"
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#undef private
#include "data_center/form_record/form_record.h"
#include "form_mgr_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
static const std::string FORM_HOST_BUNDLE_NAME = "com.form.provider.service";
const std::string FORM_BUNDLE_NAME = "formBundleName";
const int64_t FORM_ID_ONE = 1;
const int64_t FORM_ID_ZERO = 0;
const int64_t FORM_USER_UIDS_ZERO = 0;

extern void MockIsBaseValidPass(ErrCode mockRet);
extern void MockAskForProviderData(ErrCode mockRet);
extern void MockUpdateByProviderData(ErrCode mockRet);
extern void MockIsSystemOverload(bool mockBool);
extern void MockIsFormInvisible(bool mockBool);
extern void MockIsScreenOff(bool mockBool);
extern void MockIsHealthyControl(bool mockBool);

namespace {
class FmsFormCheckMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormCheckMgrTest::SetUpTestCase() {}
void FmsFormCheckMgrTest::TearDownTestCase() {}
void FmsFormCheckMgrTest::SetUp() {}
void FmsFormCheckMgrTest::TearDown() {}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_ActiveUserChecker_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_ActiveUserChecker_001 start";

    int callingUid = 1;
    FormRecord formRecord;
    formRecord.providerUserId = callingUid;
    Want reqWant;
    CheckValidFactor reqFactor;
    reqFactor.record = formRecord;
    reqFactor.want = reqWant;
    ActiveUserChecker::GetInstance().CheckValid(reqFactor);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, ActiveUserChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_ActiveUserChecker_001 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_AddFinishChecker_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_AddFinishChecker_002 start";

    CheckValidFactor reqFactor;
    reqFactor.formId = FORM_ID_ONE;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, AddFinishChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_AddFinishChecker_002 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_CallingBundleChecker_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_CallingBundleChecker_003 start";

    CheckValidFactor reqFactor;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, CallingBundleChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_CallingBundleChecker_003 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_CallingUserChecker_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_CallingUserChecker_004 start";

    int callingUid = 1;
    CheckValidFactor reqFactor;
    reqFactor.callingUid = callingUid;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, CallingUserChecker::GetInstance().CheckValid(reqFactor));

    FormRecord formRecord;
    formRecord.uid = callingUid;
    reqFactor.record = formRecord;
    EXPECT_EQ(ERR_OK, CallingUserChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_CallingUserChecker_004 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_SelfFormChecker_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_SelfFormChecker_005 start";

    CheckValidFactor reqFactor;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, SelfFormChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_SelfFormChecker_005 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_SystemAppChecker_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_SystemAppChecker_006 start";

    CheckValidFactor reqFactor;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, SystemAppChecker::GetInstance().CheckValid(reqFactor));

    FormRecord formRecord;
    formRecord.isSystemApp = true;
    reqFactor.record = formRecord;
    EXPECT_EQ(ERR_OK, SystemAppChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_SystemAppChecker_006 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormDataRefreshImpl_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormDataRefreshImpl_007 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormDataRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    MockUpdateByProviderData(ERR_APPEXECFWK_FORM_DISABLE_REFRESH);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_DISABLE_REFRESH, FormDataRefreshImpl::GetInstance().RefreshFormInput(data));

    MockUpdateByProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormDataRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormDataRefreshImpl_007 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormForceRefreshImpl_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormForceRefreshImpl_008 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormForceRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormForceRefreshImpl::GetInstance().RefreshFormInput(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormForceRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormForceRefreshImpl_008 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormHostRefreshImpl_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormHostRefreshImpl_009 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormHostRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    MockIsHealthyControl(true);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsHealthyControl(false);
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsScreenOff(false);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormHostRefreshImpl::GetInstance().RefreshFormInput(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormHostRefreshImpl_009 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormNetConnRefreshImpl_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNetConnRefreshImpl_010 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    MockIsHealthyControl(true);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsHealthyControl(false);
    MockIsFormInvisible(true);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsFormInvisible(false);
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsScreenOff(false);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNetConnRefreshImpl_010 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormNextTimeRefreshImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormNextTimeRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012 start";

    RefreshData data;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
        FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));

    MockIsBaseValidPass(ERR_OK);
    MockIsHealthyControl(true);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));

    MockIsHealthyControl(false);
    MockIsFormInvisible(true);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));

    MockIsFormInvisible(false);
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));

    MockIsScreenOff(false);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormTimerRefreshImpl_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormTimerRefreshImpl_013 start";

    RefreshData data;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormTimerRefreshImpl::GetInstance().RefreshFormInput(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormTimerRefreshImpl_013 end";
}
}