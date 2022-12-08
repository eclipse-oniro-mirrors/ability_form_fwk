/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "form_acquire_connection.h"
#include "form_bundle_event_callback.h"
#include "form_cache_mgr.h"
#include "form_cast_temp_connection.h"
#include "form_delete_connection.h"
#include "form_event_handler.h"
#include "form_host_record.h"
#include "form_item_info.h"
#include "form_refresh_connection.h"
#include "form_refresh_limiter.h"
#include "form_share_connection.h"
#include "form_supply_callback.h"
#include "form_util.h"
#include "free_install_status_callback_stub.h"
#undef private
#include "ipc_types.h"
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormRefreshConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

class MockFreeInstallStatusCallBackStub : public FreeInstallStatusCallBackStub {
public:
    MockFreeInstallStatusCallBackStub() = default;
    virtual ~MockFreeInstallStatusCallBackStub() = default;

    virtual void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId)
    {}
};

void FmsFormRefreshConnectionTest::SetUp()
{}

void FmsFormRefreshConnectionTest::TearDown()
{}

/**
 * @tc.name: FormCacheMgr_001
 * @tc.desc: test GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_001 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.GetData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_001 end";
}

/**
 * @tc.name: FormCacheMgr_002
 * @tc.desc: test GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_002 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "";
    int64_t formIds = 2;
    formCacheMgr.cacheData_.emplace(formIds, data);
    EXPECT_EQ(false, formCacheMgr.GetData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_002 end";
}

/**
 * @tc.name: FormCacheMgr_003
 * @tc.desc: test DeleteData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_003 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.DeleteData(formId));
    GTEST_LOG_(INFO) << "FormCacheMgr_003 end";
}

/**
 * @tc.name: FormCacheMgr_004
 * @tc.desc: test UpdateData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_004 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    EXPECT_EQ(false, formCacheMgr.UpdateData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_004 end";
}

/**
 * @tc.name: FormCacheMgr_005
 * @tc.desc: test UpdateData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_005 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.UpdateData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_005 end";
}

/**
 * @tc.name: FormCacheMgr_006
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_006 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    int64_t formIds = 2;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formIds, data);
    EXPECT_EQ(false, formCacheMgr.IsExist(formId));
    GTEST_LOG_(INFO) << "FormCacheMgr_006 end";
}

/**
 * @tc.name: FormRefreshConnection_001
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    FormRefreshConnection formRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formRefreshConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 end";
}

/**
 * @tc.name: FormUtil_001
 * @tc.desc: test PaddingUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_001 start";
    FormUtil formUtil;
    uint64_t formId = 0;
    uint64_t udidHash = 3;
    EXPECT_EQ(3, formUtil.PaddingUdidHash(formId, udidHash));
    GTEST_LOG_(INFO) << "FormUtil_001 end";
}

/**
 * @tc.name: FormUtil_002
 * @tc.desc: test GenerateUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_002 start";
    FormUtil formUtil;
    int64_t udidHash = 100;
    EXPECT_EQ(true, formUtil.GenerateUdidHash(udidHash));
    GTEST_LOG_(INFO) << "FormUtil_002 end";
}

/**
 * @tc.name: FormSupplyCallback_001
 * @tc.desc: test AddConnection function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = nullptr;
    formSupplyCallback.AddConnection(connection);
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 end";
}

/**
 * @tc.name: FormSupplyCallback_002
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = nullptr;
    EXPECT_EQ(false, formSupplyCallback.CanDisconnect(connection));
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 end";
}

/**
 * @tc.name: FormSupplyCallback_003
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_003 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = new (std::nothrow) FormAbilityConnection();
    EXPECT_EQ(false, formSupplyCallback.CanDisconnect(connection));
    GTEST_LOG_(INFO) << "FormSupplyCallback_003 end";
}

/**
 * @tc.name: FormShareConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormShareConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    std::string deviceId = "cc";
    int64_t formShareRequestCode = 2;
    FormShareConnection formShareConnection(formId, bundleName, abilityName, deviceId, formShareRequestCode);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t resultCode = 3;
    formShareConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormShareConnection_001 end";
}

/**
 * @tc.name: FormHostRecord_001
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_001 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    bool flag = true;
    formHostRecord.SetEnableRefresh(formId, flag);
    GTEST_LOG_(INFO) << "FormHostRecord_001 end";
}

/**
 * @tc.name: FormHostRecord_002
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_002 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    EXPECT_EQ(false, formHostRecord.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_002 end";
}

/**
 * @tc.name: FormHostRecord_003
 * @tc.desc: test SetEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_003 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    bool enable = true;
    formHostRecord.SetEnableUpdate(formId, enable);
    GTEST_LOG_(INFO) << "FormHostRecord_003 end";
}

/**
 * @tc.name: FormHostRecord_004
 * @tc.desc: test SetEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_004 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    bool enable = true;
    formHostRecord.forms_.emplace(formId, enable);
    formHostRecord.SetEnableUpdate(formId, enable);
    GTEST_LOG_(INFO) << "FormHostRecord_004 end";
}

/**
 * @tc.name: FormHostRecord_005
 * @tc.desc: test IsEnableUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_005 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    bool enable = true;
    formHostRecord.enableUpdateMap_.emplace(formId, enable);
    EXPECT_EQ(true, formHostRecord.IsEnableUpdate(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_005 end";
}

/**
 * @tc.name: FormHostRecord_006
 * @tc.desc: test IsNeedRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_006 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    EXPECT_EQ(false, formHostRecord.IsNeedRefresh(formId));
    GTEST_LOG_(INFO) << "FormHostRecord_006 end";
}

/**
 * @tc.name: FormHostRecord_007
 * @tc.desc: test OnAcquire function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_007 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    FormRecord record;
    formHostRecord.OnAcquire(formId, record);
    GTEST_LOG_(INFO) << "FormHostRecord_007 end";
}

/**
 * @tc.name: FormHostRecord_008
 * @tc.desc: test OnUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_008 start";
    FormHostRecord formHostRecord;
    int64_t formId = 1;
    FormRecord record;
    formHostRecord.formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord.OnUpdate(formId, record);
    GTEST_LOG_(INFO) << "FormHostRecord_008 end";
}

/**
 * @tc.name: FormHostRecord_009
 * @tc.desc: test OnFormUninstalled function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_009 start";
    FormHostRecord formHostRecord;
    std::vector<int64_t> formIds;
    formHostRecord.formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord.OnFormUninstalled(formIds);
    GTEST_LOG_(INFO) << "FormHostRecord_009 end";
}

/**
 * @tc.name: FormHostRecord_010
 * @tc.desc: test OnAcquireState function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_010 start";
    FormHostRecord formHostRecord;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    formHostRecord.formHostCallback_ = std::make_shared<FormHostCallback>();
    formHostRecord.OnAcquireState(state, want);
    GTEST_LOG_(INFO) << "FormHostRecord_010 end";
}

/**
 * @tc.name: FormHostRecord_011
 * @tc.desc: test AddDeathRecipient function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormHostRecord_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostRecord_011 start";
    FormHostRecord formHostRecord;
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    formHostRecord.AddDeathRecipient(deathRecipient);
    GTEST_LOG_(INFO) << "FormHostRecord_011 end";
}

/**
 * @tc.name: FormAcquireConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormAcquireConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAcquireConnection_001 start";
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    FormAcquireConnection formAcquireConnection(formId, info, wantParams, hostToken);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formAcquireConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnection_001 end";
}

/**
 * @tc.name: FormCastTempConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCastTempConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCastTempConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormCastTempConnection formCastTempConnection(formId, bundleName, abilityName);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formCastTempConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormCastTempConnection_001 end";
}

/**
 * @tc.name: FormDeleteConnection_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormDeleteConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormDeleteConnection_001 start";
    int64_t formId = 1;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    FormDeleteConnection formDeleteConnection(formId, bundleName, abilityName);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formDeleteConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormDeleteConnection_001 end";
}

/**
 * @tc.name: FormEventHandler_001
 * @tc.desc: test OnAbilityConnectDone function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormEventHandler_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventHandler_001 start";
    std::shared_ptr<AppExecFwk::EventRunner> runner = nullptr;
    FormEventHandler formEventHandler(runner);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Pointer(nullptr, nullptr);
    formEventHandler.ProcessEvent(event);
    GTEST_LOG_(INFO) << "FormEventHandler_001 end";
}

/**
 * @tc.name: FormEventHandler_002
 * @tc.desc: test UnregisterEventTimeoutObserver function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormEventHandler_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventHandler_002 start";
    std::shared_ptr<AppExecFwk::EventRunner> runner = nullptr;
    FormEventHandler formEventHandler(runner);
    std::shared_ptr<FormEventTimeoutObserver> observer = nullptr;
    formEventHandler.observers_.insert(observer);
    formEventHandler.UnregisterEventTimeoutObserver(observer);
    GTEST_LOG_(INFO) << "FormEventHandler_002 end";
}

/**
 * @tc.name: FormItemInfo_001
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_001 start";
    FormItemInfo formItemInfo;
    formItemInfo.providerBundleName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_001 end";
}

/**
 * @tc.name: FormItemInfo_002
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_002 start";
    FormItemInfo formItemInfo;
    formItemInfo.moduleName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_002 end";
}

/**
 * @tc.name: FormItemInfo_003
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_003 start";
    FormItemInfo formItemInfo;
    formItemInfo.abilityName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_003 end";
}

/**
 * @tc.name: FormItemInfo_004
 * @tc.desc: test IsValidItem function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormItemInfo_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormItemInfo_004 start";
    FormItemInfo formItemInfo;
    formItemInfo.formName_ = "aa";
    EXPECT_EQ(false, formItemInfo.IsValidItem());
    GTEST_LOG_(INFO) << "FormItemInfo_004 end";
}

/**
 * @tc.name: FormRefreshLimiter_001
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_001 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT;
    limitInfo.isReported = true;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(false, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_001 end";
}

/**
 * @tc.name: FormRefreshLimiter_002
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_002 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT;
    limitInfo.isReported = false;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(false, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_002 end";
}

/**
 * @tc.name: FormRefreshLimiter_003
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_003 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    limitInfo.isReported = false;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(true, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_003 end";
}

/**
 * @tc.name: FormRefreshLimiter_004
 * @tc.desc: test IsEnableRefresh function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_004 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    limitInfo.isReported = true;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    EXPECT_EQ(true, formRefreshLimiter.IsEnableRefresh(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_004 end";
}

/**
 * @tc.name: FormRefreshLimiter_005
 * @tc.desc: test GetRefreshCount function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_005 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    EXPECT_EQ(-1, formRefreshLimiter.GetRefreshCount(formId));
    GTEST_LOG_(INFO) << "FormRefreshLimiter_005 end";
}

/**
 * @tc.name: FormRefreshLimiter_006
 * @tc.desc: test Increase function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_006 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    formRefreshLimiter.Increase(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_006 end";
}

/**
 * @tc.name: FormRefreshLimiter_007
 * @tc.desc: test MarkRemind function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_007 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    formRefreshLimiter.MarkRemind(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_007 end";
}

/**
 * @tc.name: FormRefreshLimiter_008
 * @tc.desc: test MarkRemind function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_008 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.refreshCount = Constants::LIMIT_COUNT - 1;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter.MarkRemind(formId);
    GTEST_LOG_(INFO) << "FormRefreshLimiter_008 end";
}

/**
 * @tc.name: FormRefreshLimiter_009
 * @tc.desc: test GetRemindList function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_009 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.remindFlag = false;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter.GetRemindList();
    GTEST_LOG_(INFO) << "FormRefreshLimiter_009 end";
}

/**
 * @tc.name: FormRefreshLimiter_010
 * @tc.desc: test GetRemindListAndResetLimit function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshLimiter_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshLimiter_010 start";
    FormRefreshLimiter formRefreshLimiter;
    int64_t formId = 1;
    LimitInfo limitInfo;
    limitInfo.remindFlag = true;
    formRefreshLimiter.limiterMap_.emplace(formId, limitInfo);
    formRefreshLimiter.GetRemindListAndResetLimit();
    GTEST_LOG_(INFO) << "FormRefreshLimiter_010 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_001
 * @tc.desc: test GetRemindListAndResetLimit function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_001 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(ERR_INVALID_VALUE, mockFreeInstallStatusCallBackStub.OnInstallFinishedInner(data, reply));
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_001 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_002
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_002 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_INVALID_STATE, mockFreeInstallStatusCallBackStub.OnRemoteRequest(code, data, reply, option));
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_002 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_003
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_003 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string remoteDescriptor = u"ohos.aafwk.IAtomicServiceStatusCallback";
    data.WriteInterfaceToken(remoteDescriptor);
    mockFreeInstallStatusCallBackStub.OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_003 end";
}

/**
 * @tc.name: FreeInstallStatusCallBackStub_004
 * @tc.desc: test OnRemoteRequest function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FreeInstallStatusCallBackStub_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_004 start";
    MockFreeInstallStatusCallBackStub mockFreeInstallStatusCallBackStub;
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string remoteDescriptor = u"ohos.aafwk.IAtomicServiceStatusCallback";
    data.WriteInterfaceToken(remoteDescriptor);
    mockFreeInstallStatusCallBackStub.OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "FreeInstallStatusCallBackStub_004 end";
}

/**
 * @tc.name: FormBundleEventCallback_001
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_001 start";
    std::shared_ptr<FormEventHandler> eventHandler = nullptr;
    FormBundleEventCallback formBundleEventCallback(eventHandler);
    EventFwk::CommonEventData eventData;
    formBundleEventCallback.OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_001 end";
}

/**
 * @tc.name: FormBundleEventCallback_002
 * @tc.desc: test OnReceiveEvent function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormBundleEventCallback_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormBundleEventCallback_002 start";
    std::shared_ptr<FormEventHandler> eventHandler = std::make_shared<FormEventHandler>(EventRunner::Create());
    FormBundleEventCallback formBundleEventCallback(eventHandler);
    EventFwk::CommonEventData eventData;
    AAFwk::Want want = eventData.GetWant();
    std::string action = "";
    want.SetAction(action);
    std::string bundleName = "";
    want.SetBundle(bundleName);
    formBundleEventCallback.OnReceiveEvent(eventData);
    GTEST_LOG_(INFO) << "FormBundleEventCallback_002 end";
}
}