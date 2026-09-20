/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "form_mgr_errors.h"
#include "form_service_constants.h"
#include "form_cross_device_constants.h"
#include "form_service_info.h"

#define private public
#define protected public
#include "feature/service_discovery/form_service_proxy.h"
#undef private
#undef protected

#include "inner/mock_dm_service_adapter.h"
#include "inner/mock_form_util.h"
#include "inner/mock_form_bms_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedHardware;

namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int64_t TEST_SERVICE_ID = 200;
constexpr int64_t DM_ASSIGNED_SERVICE_ID = 1;
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_SERVICE_NAME = "test-svc";
const std::string TEST_DISPLAY_NAME = "TestDisplayName";
const std::string EXPECTED_SERVICE_KEY = "com.test.bundle|100";

ErrCode g_onStartListenRet = ERR_OK;
bool g_onStopListenCalled = false;

FormHostServiceInfo MakeValidInfo()
{
    FormHostServiceInfo info;
    info.serviceName = TEST_SERVICE_NAME;
    info.serviceDisplayName = TEST_DISPLAY_NAME;
    info.displayId = "0";
    info.customData = "";
    return info;
}

DmRegisterServiceInfo MakeRegInfo()
{
    DmRegisterServiceInfo regInfo;
    regInfo.userId = TEST_USER_ID;
    regInfo.displayId = 0;
    regInfo.serviceOwnerPkgName = TEST_BUNDLE_NAME;
    regInfo.serviceType = FORM_CD_SERVICE_TYPE;
    regInfo.serviceName = TEST_SERVICE_NAME;
    regInfo.serviceDisplayName = TEST_DISPLAY_NAME;
    regInfo.customData = "{}";
    regInfo.dataLen = 2;
    regInfo.description = TEST_DISPLAY_NAME;
    regInfo.serviceCode = TEST_SERVICE_NAME;
    return regInfo;
}

ServiceTransportHooks MakeHooks()
{
    ServiceTransportHooks hooks;
    hooks.onStartListen = [](int64_t) -> ErrCode { return g_onStartListenRet; };
    hooks.onStopListen = [](int64_t) { g_onStopListenCalled = true; };
    return hooks;
}
} // namespace

class FmsFormServiceProxyTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
protected:
    std::shared_ptr<IDmServiceAdapter> dmAdapter_;
    std::shared_ptr<FormServiceProxy> proxy_;
};

void FmsFormServiceProxyTest::SetUp()
{
    ResetDmServiceAdapterMock();
    MockGetCurrentAccountIdRet(TEST_USER_ID);
    MockGetCallerUserId(TEST_USER_ID);
    MockGetCallerBundleName(ERR_OK, TEST_BUNDLE_NAME);
    g_onStartListenRet = ERR_OK;
    g_onStopListenCalled = false;
    dmAdapter_ = std::make_shared<DmServiceAdapter>();
    proxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, ServiceTransportHooks{});
}

void FmsFormServiceProxyTest::TearDown()
{
    proxy_.reset();
    dmAdapter_.reset();
    ResetDmServiceAdapterMock();
}

// ===================== ValidateInput =====================

/**
 * @tc.name: ValidateInput_001
 * @tc.desc: Verify ValidateInput returns error when serviceName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ValidateInput_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ValidateInput_001 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.serviceName = "";
    EXPECT_EQ(proxy_->ValidateInput(info), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ValidateInput_001 end";
}

/**
 * @tc.name: ValidateInput_002
 * @tc.desc: Verify ValidateInput returns error when serviceName exceeds max length.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ValidateInput_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ValidateInput_002 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.serviceName = std::string(static_cast<size_t>(FORM_SERVICE_MAX_SERVICE_NAME) + 1, 'a');
    EXPECT_EQ(proxy_->ValidateInput(info), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ValidateInput_002 end";
}

/**
 * @tc.name: ValidateInput_003
 * @tc.desc: Verify ValidateInput returns error when serviceDisplayName is too short.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ValidateInput_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ValidateInput_003 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.serviceDisplayName = "short";
    EXPECT_EQ(proxy_->ValidateInput(info), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ValidateInput_003 end";
}

/**
 * @tc.name: ValidateInput_004
 * @tc.desc: Verify ValidateInput returns error when serviceDisplayName exceeds max length.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ValidateInput_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ValidateInput_004 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.serviceDisplayName = std::string(static_cast<size_t>(FORM_SERVICE_MAX_DISPLAYNAME) + 1, 'a');
    EXPECT_EQ(proxy_->ValidateInput(info), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ValidateInput_004 end";
}

/**
 * @tc.name: ValidateInput_005
 * @tc.desc: Verify ValidateInput returns ERR_OK when all fields are valid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ValidateInput_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ValidateInput_005 start";
    FormHostServiceInfo info = MakeValidInfo();
    EXPECT_EQ(proxy_->ValidateInput(info), ERR_OK);
    GTEST_LOG_(INFO) << "ValidateInput_005 end";
}

// ===================== ResolveCallerIdentity =====================

/**
 * @tc.name: ResolveCallerIdentity_001
 * @tc.desc: Verify ResolveCallerIdentity fails when GetCallerBundleName returns error.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ResolveCallerIdentity_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_001 start";
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_INVALID_PARAM, "");
    int32_t userId = -1;
    std::string ownerPkgName;
    EXPECT_EQ(proxy_->ResolveCallerIdentity(userId, ownerPkgName), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_001 end";
}

/**
 * @tc.name: ResolveCallerIdentity_002
 * @tc.desc: Verify ResolveCallerIdentity fails when bundle name is empty despite ERR_OK return.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ResolveCallerIdentity_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_002 start";
    MockGetCallerBundleName(ERR_OK, "");
    int32_t userId = -1;
    std::string ownerPkgName;
    EXPECT_EQ(proxy_->ResolveCallerIdentity(userId, ownerPkgName), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_002 end";
}

/**
 * @tc.name: ResolveCallerIdentity_003
 * @tc.desc: Verify ResolveCallerIdentity succeeds and populates userId and ownerPkgName.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, ResolveCallerIdentity_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_003 start";
    int32_t userId = -1;
    std::string ownerPkgName;
    EXPECT_EQ(proxy_->ResolveCallerIdentity(userId, ownerPkgName), ERR_OK);
    EXPECT_EQ(userId, TEST_USER_ID);
    EXPECT_EQ(ownerPkgName, TEST_BUNDLE_NAME);
    GTEST_LOG_(INFO) << "ResolveCallerIdentity_003 end";
}

// ===================== BuildServiceKey =====================

/**
 * @tc.name: BuildServiceKey_001
 * @tc.desc: Verify BuildServiceKey produces correct concatenated key.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, BuildServiceKey_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BuildServiceKey_001 start";
    std::string key = proxy_->BuildServiceKey(TEST_BUNDLE_NAME, TEST_USER_ID);
    EXPECT_EQ(key, EXPECTED_SERVICE_KEY);
    GTEST_LOG_(INFO) << "BuildServiceKey_001 end";
}

// ===================== BuildRegisterInfo =====================

/**
 * @tc.name: BuildRegisterInfo_001
 * @tc.desc: Verify BuildRegisterInfo uses default displayId when ConvertStringToInt64 fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, BuildRegisterInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BuildRegisterInfo_001 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.displayId = "invalid";
    auto regInfo = proxy_->BuildRegisterInfo(info, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_EQ(regInfo.displayId, FORM_CD_DEFAULT_DISPLAY_ID);
    GTEST_LOG_(INFO) << "BuildRegisterInfo_001 end";
}

/**
 * @tc.name: BuildRegisterInfo_002
 * @tc.desc: Verify BuildRegisterInfo parses displayId when valid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, BuildRegisterInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BuildRegisterInfo_002 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.displayId = "123";
    auto regInfo = proxy_->BuildRegisterInfo(info, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_EQ(regInfo.displayId, 123);
    GTEST_LOG_(INFO) << "BuildRegisterInfo_002 end";
}

/**
 * @tc.name: BuildRegisterInfo_003
 * @tc.desc: Verify BuildRegisterInfo uses "{}" when customData is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, BuildRegisterInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BuildRegisterInfo_003 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.customData = "";
    auto regInfo = proxy_->BuildRegisterInfo(info, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_EQ(regInfo.customData, "{}");
    GTEST_LOG_(INFO) << "BuildRegisterInfo_003 end";
}

/**
 * @tc.name: BuildRegisterInfo_004
 * @tc.desc: Verify BuildRegisterInfo uses info.customData when non-empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, BuildRegisterInfo_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BuildRegisterInfo_004 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.customData = R"({"key":"val"})";
    auto regInfo = proxy_->BuildRegisterInfo(info, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_EQ(regInfo.customData, R"({"key":"val"})");
    GTEST_LOG_(INFO) << "BuildRegisterInfo_004 end";
}

// ===================== RegisterWithDm =====================

/**
 * @tc.name: RegisterWithDm_001
 * @tc.desc: Verify RegisterWithDm fails when RegisterServiceInfo returns error.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, RegisterWithDm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RegisterWithDm_001 start";
    MockRegisterServiceInfo(-1, 0);
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->RegisterWithDm(MakeRegInfo(), serviceId), ERR_APPEXECFWK_FORM_SERVICE_PUBLISH_FAILED);
    EXPECT_EQ(serviceId, -1);
    GTEST_LOG_(INFO) << "RegisterWithDm_001 end";
}

/**
 * @tc.name: RegisterWithDm_002
 * @tc.desc: Verify RegisterWithDm rolls back UnRegisterServiceInfo when StartPublishService fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, RegisterWithDm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RegisterWithDm_002 start";
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(-1);
    int32_t callsBefore = GetUnRegisterServiceInfoCallCount();
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->RegisterWithDm(MakeRegInfo(), serviceId), ERR_APPEXECFWK_FORM_SERVICE_PUBLISH_FAILED);
    EXPECT_GT(GetUnRegisterServiceInfoCallCount(), callsBefore);
    GTEST_LOG_(INFO) << "RegisterWithDm_002 end";
}

/**
 * @tc.name: RegisterWithDm_003
 * @tc.desc: Verify RegisterWithDm succeeds with no onStartListen hook.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, RegisterWithDm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RegisterWithDm_003 start";
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(0);
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->RegisterWithDm(MakeRegInfo(), serviceId), ERR_OK);
    EXPECT_EQ(serviceId, DM_ASSIGNED_SERVICE_ID);
    GTEST_LOG_(INFO) << "RegisterWithDm_003 end";
}

/**
 * @tc.name: RegisterWithDm_004
 * @tc.desc: Verify RegisterWithDm rolls back when onStartListen hook returns error.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, RegisterWithDm_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RegisterWithDm_004 start";
    g_onStartListenRet = ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE;
    proxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, MakeHooks());
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(0);
    int32_t unregBefore = GetUnRegisterServiceInfoCallCount();
    int32_t stopPubBefore = GetStopPublishServiceCallCount();
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->RegisterWithDm(MakeRegInfo(), serviceId), ERR_APPEXECFWK_FORM_CD_SOFTBUS_UNAVAILABLE);
    EXPECT_GT(GetStopPublishServiceCallCount(), stopPubBefore);
    EXPECT_GT(GetUnRegisterServiceInfoCallCount(), unregBefore);
    GTEST_LOG_(INFO) << "RegisterWithDm_004 end";
}

/**
 * @tc.name: RegisterWithDm_005
 * @tc.desc: Verify RegisterWithDm succeeds when onStartListen returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, RegisterWithDm_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RegisterWithDm_005 start";
    g_onStartListenRet = ERR_OK;
    proxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, MakeHooks());
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(0);
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->RegisterWithDm(MakeRegInfo(), serviceId), ERR_OK);
    EXPECT_EQ(serviceId, DM_ASSIGNED_SERVICE_ID);
    GTEST_LOG_(INFO) << "RegisterWithDm_005 end";
}

// ===================== Register =====================

/**
 * @tc.name: Register_001
 * @tc.desc: Verify Register returns error when ValidateInput fails (empty serviceName).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Register_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Register_001 start";
    FormHostServiceInfo info = MakeValidInfo();
    info.serviceName = "";
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->Register(info, serviceId), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "Register_001 end";
}

/**
 * @tc.name: Register_002
 * @tc.desc: Verify Register returns existing serviceId when already registered.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Register_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Register_002 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.userId = TEST_USER_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);

    FormHostServiceInfo info = MakeValidInfo();
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->Register(info, serviceId), ERR_OK);
    EXPECT_EQ(serviceId, TEST_SERVICE_ID);
    GTEST_LOG_(INFO) << "Register_002 end";
}

/**
 * @tc.name: Register_003
 * @tc.desc: Verify Register succeeds and stores entry when hooks return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Register_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Register_003 start";
    g_onStartListenRet = ERR_OK;
    proxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, MakeHooks());
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(0);

    FormHostServiceInfo info = MakeValidInfo();
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->Register(info, serviceId), ERR_OK);
    EXPECT_EQ(serviceId, DM_ASSIGNED_SERVICE_ID);
    EXPECT_EQ(proxy_->localEntries_.size(), 1u);
    EXPECT_EQ(proxy_->serviceIdToKey_.count(DM_ASSIGNED_SERVICE_ID), 1u);
    GTEST_LOG_(INFO) << "Register_003 end";
}

/**
 * @tc.name: Register_004
 * @tc.desc: Verify Register succeeds without hooks (empty ServiceTransportHooks).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Register_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Register_004 start";
    MockRegisterServiceInfo(0, DM_ASSIGNED_SERVICE_ID);
    MockStartPublishService(0);

    FormHostServiceInfo info = MakeValidInfo();
    int64_t serviceId = -1;
    EXPECT_EQ(proxy_->Register(info, serviceId), ERR_OK);
    EXPECT_EQ(serviceId, DM_ASSIGNED_SERVICE_ID);
    EXPECT_EQ(proxy_->localEntries_.size(), 1u);
    GTEST_LOG_(INFO) << "Register_004 end";
}

// ===================== Unregister =====================

/**
 * @tc.name: Unregister_001
 * @tc.desc: Verify Unregister fails when ResolveCallerIdentity fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Unregister_001 start";
    MockGetCallerBundleName(ERR_APPEXECFWK_FORM_INVALID_PARAM, "");
    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "Unregister_001 end";
}

/**
 * @tc.name: Unregister_002
 * @tc.desc: Verify Unregister returns NOT_EXIST when service not found in localEntries_.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Unregister_002 start";
    proxy_->localEntries_.clear();
    proxy_->serviceIdToKey_.clear();
    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_APPEXECFWK_FORM_SERVICE_NOT_EXIST);
    GTEST_LOG_(INFO) << "Unregister_002 end";
}

/**
 * @tc.name: Unregister_003
 * @tc.desc: Verify Unregister returns NOT_SELF when serviceId does not match caller's.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Unregister_003 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID + 999), ERR_APPEXECFWK_FORM_SERVICE_NOT_SELF);
    GTEST_LOG_(INFO) << "Unregister_003 end";
}

/**
 * @tc.name: Unregister_004
 * @tc.desc: Verify Unregister succeeds and calls onStopListen when hooks are set.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "Unregister_004 start";
    g_onStopListenCalled = false;
    proxy_ = std::make_shared<FormServiceProxy>(dmAdapter_, MakeHooks());
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    entry.info.userId = TEST_USER_ID;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;
    MockStopPublishService(0);
    MockUnRegisterServiceInfo(0);

    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_OK);
    EXPECT_TRUE(g_onStopListenCalled);
    EXPECT_EQ(proxy_->localEntries_.count(EXPECTED_SERVICE_KEY), 0u);
    EXPECT_EQ(proxy_->serviceIdToKey_.count(TEST_SERVICE_ID), 0u);
    GTEST_LOG_(INFO) << "Unregister_004 end";
}

/**
 * @tc.name: Unregister_005
 * @tc.desc: Verify Unregister succeeds without hooks (empty ServiceTransportHooks).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unregister_005 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    entry.info.userId = TEST_USER_ID;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;
    MockStopPublishService(0);
    MockUnRegisterServiceInfo(0);

    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_OK);
    EXPECT_EQ(proxy_->localEntries_.count(EXPECTED_SERVICE_KEY), 0u);
    GTEST_LOG_(INFO) << "Unregister_005 end";
}

/**
 * @tc.name: Unregister_006
 * @tc.desc: Verify Unregister still succeeds when StopPublishService fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unregister_006 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    entry.info.userId = TEST_USER_ID;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;
    MockStopPublishService(-1);
    MockUnRegisterServiceInfo(0);

    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_OK);
    EXPECT_EQ(proxy_->localEntries_.count(EXPECTED_SERVICE_KEY), 0u);
    GTEST_LOG_(INFO) << "Unregister_006 end";
}

/**
 * @tc.name: Unregister_007
 * @tc.desc: Verify Unregister still succeeds when UnRegisterServiceInfo fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Unregister_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Unregister_007 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    entry.info.userId = TEST_USER_ID;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;
    MockStopPublishService(0);
    MockUnRegisterServiceInfo(-1);

    EXPECT_EQ(proxy_->Unregister(TEST_SERVICE_ID), ERR_OK);
    EXPECT_EQ(proxy_->localEntries_.count(EXPECTED_SERVICE_KEY), 0u);
    GTEST_LOG_(INFO) << "Unregister_007 end";
}

// ===================== GetUserIdByServiceId =====================

/**
 * @tc.name: GetUserIdByServiceId_001
 * @tc.desc: Verify GetUserIdByServiceId returns false when serviceId not found.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, GetUserIdByServiceId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_001 start";
    proxy_->localEntries_.clear();
    proxy_->serviceIdToKey_.clear();
    int32_t userId = -1;
    EXPECT_FALSE(proxy_->GetUserIdByServiceId(TEST_SERVICE_ID, userId));
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_001 end";
}

/**
 * @tc.name: GetUserIdByServiceId_002
 * @tc.desc: Verify GetUserIdByServiceId returns true with correct userId when found.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, GetUserIdByServiceId_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_002 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.userId = TEST_USER_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;

    int32_t userId = -1;
    EXPECT_TRUE(proxy_->GetUserIdByServiceId(TEST_SERVICE_ID, userId));
    EXPECT_EQ(userId, TEST_USER_ID);
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_002 end";
}

/**
 * @tc.name: GetUserIdByServiceId_003
 * @tc.desc: Verify GetUserIdByServiceId returns false when key in serviceIdToKey_ but entry missing.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, GetUserIdByServiceId_003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_003 start";
    proxy_->serviceIdToKey_[TEST_SERVICE_ID] = EXPECTED_SERVICE_KEY;
    proxy_->localEntries_.clear();
    int32_t userId = -1;
    EXPECT_FALSE(proxy_->GetUserIdByServiceId(TEST_SERVICE_ID, userId));
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_003 end";
}

// ===================== Dump =====================

/**
 * @tc.name: Dump_001
 * @tc.desc: Verify Dump outputs header with zero count when localEntries_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Dump_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_001 start";
    proxy_->localEntries_.clear();
    std::string result;
    proxy_->Dump(result);
    EXPECT_NE(result.find("registered: 0"), std::string::npos);
    EXPECT_EQ(result.find("serviceId="), std::string::npos);
    GTEST_LOG_(INFO) << "Dump_001 end";
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Verify Dump outputs entry details when localEntries_ has entries.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceProxyTest, Dump_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_002 start";
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.ownerPkgName = TEST_BUNDLE_NAME;
    entry.info.serviceName = TEST_SERVICE_NAME;
    proxy_->localEntries_[EXPECTED_SERVICE_KEY] = std::move(entry);

    std::string result;
    proxy_->Dump(result);
    EXPECT_NE(result.find("registered: 1"), std::string::npos);
    EXPECT_NE(result.find("serviceId=" + std::to_string(TEST_SERVICE_ID)), std::string::npos);
    EXPECT_NE(result.find(TEST_BUNDLE_NAME), std::string::npos);
    EXPECT_NE(result.find(TEST_SERVICE_NAME), std::string::npos);
    GTEST_LOG_(INFO) << "Dump_002 end";
}
