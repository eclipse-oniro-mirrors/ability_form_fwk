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
#include "mock_refresh_mgr.h"
#include "form_refresh/check_mgr/system_app_checker.h"
#include "form_refresh/check_mgr/self_form_checker.h"
#include "form_refresh/check_mgr/calling_user_checker.h"
#include "form_refresh/check_mgr/calling_bundle_checker.h"
#include "form_refresh/check_mgr/active_user_checker.h"
#include "form_refresh/check_mgr/add_finish_checker.h"
#include "form_refresh/check_mgr/untrust_app_checker.h"
#include "form_refresh/check_mgr/multi_active_users_checker.h"
#include "form_refresh/refresh_impl/form_data_refresh_impl.h"
#include "form_refresh/refresh_impl/form_force_refresh_impl.h"
#include "form_refresh/refresh_impl/form_host_refresh_impl.h"
#include "form_refresh/refresh_impl/form_net_conn_refresh_impl.h"
#include "form_refresh/refresh_impl/form_next_time_refresh_impl.h"
#include "form_refresh/refresh_impl/form_provider_refresh_impl.h"
#include "form_refresh/refresh_impl/form_refresh_after_uncontrol_impl.h"
#include "form_refresh/refresh_impl/form_timer_refresh_impl.h"
#include "form_refresh/refresh_impl/form_app_upgrade_refresh_impl.h"
#include "data_center/form_record/form_record.h"
#include "form_mgr_errors.h"
#include "common/util/form_report.h"
#include "mock_form_host_client.h"
#include "form_host/form_host_record.h"
#include "data_center/form_data_mgr.h"
#include "common/timer_mgr/form_refresh_limiter.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "feature/param_update/param_control.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
constexpr int64_t FORM_ID_ONE = 1;

namespace {
class FmsFormCheckMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<OHOS::AppExecFwk::MockFormHostClient> token_;
};

void FmsFormCheckMgrTest::SetUpTestCase() {}
void FmsFormCheckMgrTest::TearDownTestCase() {}
void FmsFormCheckMgrTest::SetUp()
{
    // token
    token_ = new (std::nothrow) OHOS::AppExecFwk::MockFormHostClient();
}
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, ActiveUserChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_ActiveUserChecker_001 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_AddFinishChecker_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_AddFinishChecker_002 start";

    CheckValidFactor reqFactor;
    FormRecord formRecord;
    formRecord.addFormFinish = false;
    reqFactor.record = formRecord;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, AddFinishChecker::GetInstance().CheckValid(reqFactor));

    formRecord.addFormFinish = true;
    reqFactor.record = formRecord;
    EXPECT_EQ(ERR_OK, AddFinishChecker::GetInstance().CheckValid(reqFactor));
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

    int64_t formId = FORM_ID_ONE;
    FormItemInfo itemInfo;
    FormDataMgr::GetInstance().AllotFormHostRecord(itemInfo, token_, formId, 0);
    reqFactor.callerToken = token_;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, SelfFormChecker::GetInstance().CheckValid(reqFactor));

    reqFactor.formId = formId;
    EXPECT_EQ(ERR_OK, SelfFormChecker::GetInstance().CheckValid(reqFactor));
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
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormDataRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.uiSyntax = FormType::JS;
    MockFormProviderUpdateForm(ERR_OK);
    EXPECT_EQ(ERR_OK, FormDataRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.uiSyntax = FormType::ETS;
    MockUpdateByProviderData(ERR_APPEXECFWK_FORM_DISABLE_REFRESH);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_DISABLE_REFRESH, FormDataRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockUpdateByProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormDataRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormDataRefreshImpl_007 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormForceRefreshImpl_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormForceRefreshImpl_008 start";

    RefreshData data;

    MockIsBaseValidPass(ERR_OK);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormForceRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormForceRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormForceRefreshImpl_008 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormHostRefreshImpl_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormHostRefreshImpl_009 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.enableForm = false;
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.enableForm = true;
    MockIsAddFormFinish(false);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsNeedToFresh(true);
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.isVisible = true;
    MockIsScreenOff(false);
    MockIsNeedToFresh(false);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsNeedToFresh(true);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    data.record.isSystemApp = true;
    EXPECT_EQ(ERR_OK, FormHostRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormHostRefreshImpl_009 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormNetConnRefreshImpl_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNetConnRefreshImpl_010 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.enableForm = false;
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.enableForm = true;
    data.record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.isVisible = true;
    MockIsScreenOff(false);
    MockIsNeedToFresh(false);
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsNeedToFresh(true);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    data.record.isSystemApp = true;
    EXPECT_EQ(ERR_OK, FormNetConnRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNetConnRefreshImpl_010 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormNextTimeRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.isDataProxy = true;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormNextTimeRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormNextTimeRefreshImpl_011 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
        FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.enableForm = false;
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    data.record.enableForm = true;
    data.record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    data.record.isSystemApp = true;
    data.want.SetParam(Constants::KEY_IS_TIMER, true);
    data.want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    data.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    int64_t formId = FORM_ID_ONE;
    FormItemInfo itemInfo;
    itemInfo.SetFormId(formId);
    FormDataMgr::GetInstance().AllotFormRecord(itemInfo, 0, 0);
    FormDataMgr::GetInstance().SetRefreshType(formId, Constants::REFRESHTYPE_NETWORKCHANGED);
    data.record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    data.record.isVisible = true;
    MockIsScreenOff(false);
    MockIsNeedToFresh(false);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    MockIsNeedToFresh(true);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormRefreshAfterUncontrolImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshAfterUncontrolImpl_012 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormTimerRefreshImpl_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormTimerRefreshImpl_013 start";

    RefreshData data;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    int64_t formId = FORM_ID_ONE;
    FormItemInfo itemInfo;
    itemInfo.SetFormId(formId);
    FormDataMgr::GetInstance().AllotFormRecord(itemInfo, 0, 0);

    data.formId = formId;
    FormRecord formRecord;
    data.record = formRecord;

    FormTimer timerTask;
    timerTask.isCountTimer = true;
    timerTask.refreshType = RefreshType::TYPE_INTERVAL;
    data.formTimer = timerTask;
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    MockIsSystemOverload(true);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsSystemOverload(false);
    data.record.enableForm = false;
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.enableForm = true;
    data.record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    data.record.isSystemApp = true;
    data.want.SetParam(Constants::KEY_IS_TIMER, true);
    data.want.SetParam(Constants::KEY_TIMER_REFRESH, true);
    data.want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsScreenOff(false);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormTimerRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormTimerRefreshImpl_013 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_UntrustAppChecker_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_UntrustAppChecker_014 start";
    CheckValidFactor reqFactor;
    EXPECT_EQ(ERR_OK, UntrustAppChecker::GetInstance().CheckValid(reqFactor));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_UntrustAppChecker_014 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormAppUpgradeRefreshImpl_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormAppUpgradeRefreshImpl_015 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
        FormAppUpgradeRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    data.record.enableForm = false;
    EXPECT_EQ(ERR_OK, FormAppUpgradeRefreshImpl::GetInstance().RefreshFormRequest(data));

    data.record.enableForm = true;
    data.record.isVisible = true;
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormAppUpgradeRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormAppUpgradeRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormAppUpgradeRefreshImpl_015 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_FormProviderRefreshImpl_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormProviderRefreshImpl_016 start";

    RefreshData data;
    FormRecord formRecord;
    data.record = formRecord;
    MockIsBaseValidPass(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsBaseValidPass(ERR_OK);
    MockIsHealthyControl(true);
    EXPECT_EQ(ERR_OK, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsHealthyControl(false);
    MockIsScreenOff(true);
    EXPECT_EQ(ERR_OK, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsScreenOff(false);
    MockIsNeedToFresh(false);
    EXPECT_EQ(ERR_OK, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockIsNeedToFresh(true);
    MockAskForProviderData(ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));

    MockAskForProviderData(ERR_OK);
    EXPECT_EQ(ERR_OK, FormProviderRefreshImpl::GetInstance().RefreshFormRequest(data));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormProviderRefreshImpl_016 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_MultiActiveUsersChecker_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_MultiActiveUsersChecker_001 start";

    int callingUid = 1;
    FormRecord formRecord;
    formRecord.providerUserId = callingUid;
    Want reqWant;
    CheckValidFactor reqFactor;
    reqFactor.record = formRecord;
    reqFactor.want = reqWant;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, MultiActiveUsersChecker::GetInstance().CheckValid(reqFactor));

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_MultiActiveUsersChecker_001 end";
}

HWTEST_F(FmsFormCheckMgrTest, FmsFormCheckMgrTest_BaseFormRefresh_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_BaseFormRefresh_001 start";

    RefreshData data;
    RefreshConfig config;
    config.controlCheckFlags = CONTROL_CHECK_SYSTEM_OVERLOAD | CONTROL_CHECK_HEALTHY_CONTROL |
        CONTROL_CHECK_INVISIBLE | CONTROL_CHECK_SCREEN_OFF | CONTROL_CHECK_NEED_TO_FRESH | CONTROL_CHECK_ADD_FINISH;
    BaseFormRefresh baseFormRefresh(std::move(config));

    MockIsAddFormFinish(true);
    EXPECT_EQ(ERR_OK, baseFormRefresh.RefreshFormRequest(data));
    MockIsAddFormFinish(false);

    MockIsHealthyControl(true);
    EXPECT_EQ(ERR_OK, baseFormRefresh.RefreshFormRequest(data));
    MockIsHealthyControl(false);

    MockIsSystemOverload(true);
    EXPECT_EQ(ERR_OK, baseFormRefresh.RefreshFormRequest(data));
    MockIsSystemOverload(false);

    MockIsFormInvisible(true);
    EXPECT_EQ(ERR_OK, baseFormRefresh.RefreshFormRequest(data));
    MockIsFormInvisible(false);

    MockIsNeedToFresh(false);
    EXPECT_EQ(ERR_OK, baseFormRefresh.RefreshFormRequest(data));
    MockIsNeedToFresh(true);

    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_BaseFormRefresh_001 end";
}
}