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
#include "data_center/form_record/form_record.h"
#include "form_mgr_errors.h"
#include "form_refresh/strategy/refresh_check_mgr.h"
#include "form_refresh/strategy/refresh_control_mgr.h"
#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "form_refresh/form_refresh_mgr.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_trust_mgr.h"
#include "feature/param_update/param_control.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
constexpr int64_t FORM_ID_ONE = 1;

namespace {
class FmsFormCheckMgrTest2 : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormCheckMgrTest2::SetUpTestCase() {}
void FmsFormCheckMgrTest2::TearDownTestCase() {}
void FmsFormCheckMgrTest2::SetUp() {}
void FmsFormCheckMgrTest2::TearDown() {}

HWTEST_F(FmsFormCheckMgrTest2, FmsFormCheckMgrTest_RefreshCheckMgr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshCheckMgr_001 start";

    std::vector<int32_t> checkTypes = {};
    CheckValidFactor factor;
    EXPECT_EQ(ERR_OK, RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor));

    checkTypes = { -1 };
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor));

    checkTypes = { TYPE_SYSTEM_APP };
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor));

    factor.record.isSystemApp = true;
    EXPECT_EQ(ERR_OK, RefreshCheckMgr::GetInstance().IsBaseValidPass(checkTypes, factor));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshCheckMgr_001 end";
}

HWTEST_F(FmsFormCheckMgrTest2, FmsFormCheckMgrTest_RefreshControlMgr_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshControlMgr_002 start";

    EXPECT_EQ(false, RefreshControlMgr::GetInstance().IsSystemOverload());
#ifdef RES_SCHEDULE_ENABLE
    RefreshControlMgr::GetInstance().SetSystemOverloadFlag(true);
    EXPECT_EQ(true, RefreshControlMgr::GetInstance().IsSystemOverload());
#endif

    FormRecord record;
    record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    EXPECT_EQ(true, RefreshControlMgr::GetInstance().IsFormInvisible(record));
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    EXPECT_EQ(false, RefreshControlMgr::GetInstance().IsFormInvisible(record));

    record.moduleName = "phone_hicar";
    EXPECT_EQ(false, RefreshControlMgr::GetInstance().IsScreenOff(record));

    EXPECT_EQ(false, RefreshControlMgr::GetInstance().IsHealthyControl(record));
    record.enableForm = false;
    EXPECT_EQ(true, RefreshControlMgr::GetInstance().IsHealthyControl(record));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshControlMgr_002 end";
}

HWTEST_F(FmsFormCheckMgrTest2, FmsFormCheckMgrTest_RefreshExecMgr_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshExecMgr_003 start";
    FormRecord formRecord;
    Want reqWant;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        RefreshExecMgr::AskForProviderData(FORM_ID_ONE, formRecord, reqWant));

    FormProviderData formProviderData;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        RefreshExecMgr::UpdateByProviderData(FORM_ID_ONE, formProviderData, false));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshExecMgr_003 end";
}

HWTEST_F(FmsFormCheckMgrTest2, FmsFormCheckMgrTest_FormRefreshMgr_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshMgr_004 start";
    RefreshData data;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, FormRefreshMgr::GetInstance().RequestRefresh(data, -1));

    EXPECT_EQ(ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF, FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_DATA));
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_FormRefreshMgr_004 end";
}

HWTEST_F(FmsFormCheckMgrTest2, FmsFormCheckMgrTest_RefreshCacheMgr_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshCacheMgr_005 start";
    FormTimer timerTask(FORM_ID_ONE, true, 0);
    EXPECT_EQ(FORM_ID_ONE, timerTask.formId);
    RefreshCacheMgr::GetInstance().AddToOverloadTaskQueue(timerTask);
    RefreshCacheMgr::GetInstance().AddToOverloadTaskQueue(timerTask);
    RefreshCacheMgr::GetInstance().ConsumeOverloadTaskQueue();

    int64_t formId = FORM_ID_ONE;
    FormItemInfo itemInfo;
    itemInfo.SetFormId(formId);
    FormDataMgr::GetInstance().AllotFormRecord(itemInfo, 0, 0);
    RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(FORM_ID_ONE, true);
    RefreshCacheMgr::GetInstance().AddFlagByHealthyControl(FORM_ID_ONE, false);

    std::vector<FormRecord> formRecords;
    FormDataMgr::GetInstance().GetFormRecordsByUserId(0, formRecords);
    if (formRecords.size() > 0) {
        auto iter = formRecords.begin();
        iter->isRefreshDuringDisableForm = true;
        RefreshCacheMgr::GetInstance().ConsumeHealthyControlFlag(iter, 0);
        iter->isRefreshDuringDisableForm = false;
        iter->isUpdateDuringDisableForm = false;
        RefreshCacheMgr::GetInstance().ConsumeHealthyControlFlag(iter, 0);
        iter->isTimerRefresh = true;
    }

    RefreshCacheMgr::GetInstance().AddFlagByInvisible(FORM_ID_ONE, Constants::REFRESHTYPE_NETWORKCHANGED);
    RefreshCacheMgr::GetInstance().ConsumeInvisibleFlag(FORM_ID_ONE, 0);
    RefreshCacheMgr::GetInstance().ConsumeInvisibleFlag(FORM_ID_ONE, 0);

    FormRecord formRecord;
    Want reqWant;
    RefreshCacheMgr::GetInstance().AddFlagByScreenOff(FORM_ID_ONE, reqWant, formRecord);
    RefreshCacheMgr::GetInstance().ConsumeScreenOffFlag();

    if (formRecords.size() > 0) {
        auto iter = formRecords.begin();
        iter->needRefresh = false;
        RefreshCacheMgr::GetInstance().ConsumeScreenOffFlag();
        iter->formVisibleNotifyState = Constants::FORM_INVISIBLE;
        RefreshCacheMgr::GetInstance().ConsumeScreenOffFlag();
    }

    auto task = []() {};
    RefreshCacheMgr::GetInstance().AddRenderTask(FORM_ID_ONE, task);
    RefreshCacheMgr::GetInstance().AddRenderTask(FORM_ID_ONE, task);
    RefreshCacheMgr::GetInstance().ConsumeRenderTask(FORM_ID_ONE);
    RefreshCacheMgr::GetInstance().AddRenderTask(FORM_ID_ONE, task);
    RefreshCacheMgr::GetInstance().DelRenderTask(FORM_ID_ONE);
    RefreshCacheMgr::GetInstance().ConsumeAddUnfinishFlag(FORM_ID_ONE, 1);
    GTEST_LOG_(INFO) << "FmsFormCheckMgrTest_RefreshCacheMgr_005 end";
}
}