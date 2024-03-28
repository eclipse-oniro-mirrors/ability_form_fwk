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
#include <vector>

#include "ability_info.h"
#include "application_info.h"
#include "bundle_mgr_interface.h"
#include "gmock/gmock.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "want.h"
#define private public
#define protected public
#include "form_bms_helper.h"
#include "form_mgr_errors.h"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {

namespace AppExecFwk {
bool g_mockRegisterBundleEventCallback = false;
bool g_mockUnregisterBundleEventCallback = false;

void MockRegisterBundleEventCallback(bool mockRet)
{
    g_mockRegisterBundleEventCallback = mockRet;
}

void MockUnregisterBundleEventCallback(bool mockRet)
{
    g_mockUnregisterBundleEventCallback = mockRet;
}

class FmsFormBmsHelperTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormBmsHelperTest::SetUpTestCase() {}

void FmsFormBmsHelperTest::TearDownTestCase() {}

void FmsFormBmsHelperTest::SetUp() {}

void FmsFormBmsHelperTest::TearDown() {}

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

    bool QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo) override
    {
        return true;
    }

    bool QueryExtensionAbilityInfos(const Want &want, const int32_t &flag, const int32_t &userId,
                                    std::vector<ExtensionAbilityInfo> &extensionInfos) override
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
        bundleName = "com.form.provider.service";
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

    ErrCode GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
        std::vector<ProxyData> &proxyDatas, int32_t userId) override
    {
        return ERR_OK;
    }

    bool RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback) override
    {
        return g_mockRegisterBundleEventCallback;
    }

    bool UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback) override
    {
        return g_mockUnregisterBundleEventCallback;
    }

    ErrCode GetBundlePackInfo_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    bool setModuleRemovable_ = false;
    int32_t GetNameForUid_ = ERR_OK + 1;
};

/**
 * @tc.name: FmsFormBmsHelperTest_001
 * @tc.desc: Verify that the GetBundleMgr interface executes as expected and the return value is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_001 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_001 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_002
 * @tc.desc: Verify that the NotifyModuleRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_002 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "";
    const std::string moduleName = "";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_002 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_003
 * @tc.desc: Verify that the NotifyModuleRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_003 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "";
    const std::string moduleName = "aa";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_003 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_004
 * @tc.desc: Verify that the NotifyModuleRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_004 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "bb";
    const std::string moduleName = "";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_004 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_005
 * @tc.desc: Verify that the NotifyModuleRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_005 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "bb";
    const std::string moduleName = "aa";
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    formBmsHelper.NotifyModuleRemovable(bundleName, moduleName);
    EXPECT_NE(formBmsHelper.GetBundleMgr(), nullptr);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_005 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_006
 * @tc.desc: Verify that the NotifyModuleNotRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_006 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    const std::string moduleName = "";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_006 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_007
 * @tc.desc: Verify that the NotifyModuleNotRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_007 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "";
    const std::string moduleName = "aa";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_007 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_008
 * @tc.desc: Verify that the NotifyModuleNotRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_008 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "bb";
    const std::string moduleName = "";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_008 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_009
 * @tc.desc: Verify that the NotifyModuleNotRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_009 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "bb";
    const std::string moduleName = "aa";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_009 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_010
 * @tc.desc: Verify that the GetBundlePackInfo interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_010 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "aa";
    constexpr int32_t userId = 1;
    BundlePackInfo bundlePackInfo;
    EXPECT_FALSE(formBmsHelper.GetBundlePackInfo(bundleName, userId, bundlePackInfo));

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_FALSE(formBmsHelper.GetBundlePackInfo(bundleName, userId, bundlePackInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_010 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_011
 * @tc.desc: Verify that the GetAbilityInfoByAction interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_011 start";
    FormBmsHelper formBmsHelper;
    
    std::string action = "";
    constexpr int32_t userId = 1;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    EXPECT_FALSE(formBmsHelper.GetAbilityInfoByAction(action, userId, abilityInfo, extensionAbilityInfo));

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_FALSE(formBmsHelper.GetAbilityInfoByAction(action, userId, abilityInfo, extensionAbilityInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_011 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_012
 * @tc.desc: Verify that the GetAbilityInfoByAction interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_012 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    std::string action = "abc";
    constexpr int32_t userId = 1;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    EXPECT_FALSE(formBmsHelper.GetAbilityInfoByAction(action, userId, abilityInfo, extensionAbilityInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_012 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_013
 * @tc.desc: Verify that the GetBundleInfo interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_013 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    constexpr int32_t userId = 1;
    BundleInfo bundleInfo;
    EXPECT_FALSE(formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo));

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_FALSE(formBmsHelper.GetBundleInfo(bundleName, userId, bundleInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_013 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_014
 * @tc.desc: Verify that the GetCallerBundleName interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_014 start";
    FormBmsHelper formBmsHelper;
    std::string callerBundleName = "";
    EXPECT_EQ(formBmsHelper.GetCallerBundleName(callerBundleName), ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(formBmsHelper.GetCallerBundleName(callerBundleName), ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_014 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_015
 * @tc.desc: Verify that the GetUidByBundleName interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_015 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    constexpr int32_t userId = 1;
    EXPECT_EQ(formBmsHelper.GetUidByBundleName(bundleName, userId), -1);

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(formBmsHelper.GetUidByBundleName(bundleName, userId), 0);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_015 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_016
 * @tc.desc: Verify that the GetBundlePackInfo interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_016 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<MockBundleMgrProxy> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    bundleManager->GetBundlePackInfo_ = ERR_OK;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName = "aa";
    constexpr int32_t userId = 1;
    BundlePackInfo bundlePackInfo;
    EXPECT_TRUE(formBmsHelper.GetBundlePackInfo(bundleName, userId, bundlePackInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_016 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_017
 * @tc.desc: Verify that the NotifyModuleNotRemovable interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_017 start";
    FormBmsHelper formBmsHelper;

    const sptr<IRemoteObject> impl;
    const sptr<MockBundleMgrProxy> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    bundleManager->setModuleRemovable_ = true;
    formBmsHelper.SetBundleManager(bundleManager);
    const std::string bundleName = "bb";
    const std::string moduleName = "aa";
    formBmsHelper.NotifyModuleNotRemovable(bundleName, moduleName);
    EXPECT_NE(nullptr, formBmsHelper.GetBundleMgr());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_017 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_018
 * @tc.desc: Verify that the GetCallerBundleName interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_018 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<MockBundleMgrProxy> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    bundleManager->GetNameForUid_ = ERR_OK;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string callerBundleName = "";
    EXPECT_EQ(formBmsHelper.GetCallerBundleName(callerBundleName), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_018 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_019
 * @tc.desc: Verify that the GetBundleNameByUid interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_019 start";
    FormBmsHelper formBmsHelper;
    sptr<IRemoteObject> impl;
    sptr<MockBundleMgrProxy> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    bundleManager->GetNameForUid_ = ERR_OK;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName = "A";
    std::int32_t uid = 0;
    EXPECT_EQ(formBmsHelper.GetBundleNameByUid(uid, bundleName), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_019 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_020
 * @tc.desc: Verify that the GetBundleNameByUid interface fails to execute and returns an error code.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_020 start";
    FormBmsHelper formBmsHelper;
    std::string bundleName = "A";
    std::int32_t uid = 0;
    formBmsHelper.SetBundleManager(nullptr);
    EXPECT_EQ(formBmsHelper.GetBundleNameByUid(uid, bundleName), ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_020 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_021
 * @tc.desc: Verify that the GetBundleNameByUid interface fails to execute and returns an error code.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_021 start";
    FormBmsHelper formBmsHelper;
    sptr<IRemoteObject> impl;
    sptr<MockBundleMgrProxy> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    bundleManager->GetNameForUid_ = ERR_OK + 1;
    formBmsHelper.SetBundleManager(bundleManager);
    std::string bundleName = "A";
    std::int32_t uid = 0;
    EXPECT_EQ(formBmsHelper.GetBundleNameByUid(uid, bundleName), ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    GTEST_LOG_(INFO) << "FmsFormBmsHelperTest_021 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_022
 * @tc.desc: Verify that the GetBundleInstaller interface executes as expected and the return value is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_022 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(nullptr, formBmsHelper.GetBundleInstaller());
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_022 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_023
 * @tc.desc: Verify that the GetAbilityInfo interface executes as expected and the return value is correct.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_023 start";
    FormBmsHelper formBmsHelper;
    
    Want want;
    std::string deviceId;
    std::string bundleName = "ohos.samples.FormApplication";
    std::string moduleName = "entry";
    std::string abilityName = "FormAbility";
    std::string formName = "widget";
    constexpr int32_t dimension = 3;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, moduleName);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, dimension);

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);

    constexpr int32_t userId = 1;
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    want.SetElementName(deviceId, bundleName, "");
    EXPECT_EQ(false, formBmsHelper.GetAbilityInfo(want, userId, abilityInfo, extensionAbilityInfo));

    want.SetElementName(deviceId, bundleName, abilityName);
    EXPECT_EQ(false, formBmsHelper.GetAbilityInfo(want, userId, abilityInfo, extensionAbilityInfo));

    abilityInfo.name = "MainAbility";
    abilityInfo.bundleName = "com.ohos.launcher";
    EXPECT_EQ(true, formBmsHelper.GetAbilityInfo(want, userId, abilityInfo, extensionAbilityInfo));

    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_023 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_024
 * @tc.desc: Verify that the GetBundleInfoWithPermission interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_024 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    constexpr int32_t userId = 1;
    BundleInfo bundleInfo;
    formBmsHelper.SetBundleManager(nullptr);
    EXPECT_FALSE(formBmsHelper.GetBundleInfoWithPermission(bundleName, userId, bundleInfo));

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_FALSE(formBmsHelper.GetBundleInfoWithPermission(bundleName, userId, bundleInfo));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_024 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_025
 * @tc.desc: Verify that the GetCompileMode interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_025 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    const std::string moduleName = "";
    int32_t userId = 1;
    int32_t compileMode = 1;
    formBmsHelper.SetBundleManager(nullptr);
    EXPECT_FALSE(formBmsHelper.GetCompileMode(bundleName, moduleName, userId, compileMode));

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_FALSE(formBmsHelper.GetCompileMode(bundleName, moduleName, userId, compileMode));
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_025 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_026
 * @tc.desc: Verify that the GetProxyDataInfos interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_026 start";
    FormBmsHelper formBmsHelper;
    const std::string bundleName = "";
    const std::string moduleName = "";
    constexpr int32_t userId = 1;
    std::vector<ProxyData> proxyData;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(formBmsHelper.GetProxyDataInfos(bundleName, moduleName, userId, proxyData), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_026 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_027
 * @tc.desc: Verify that the RegisterBundleEventCallback interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_027 start";
    FormBmsHelper formBmsHelper;

    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(formBmsHelper.RegisterBundleEventCallback(), ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockRegisterBundleEventCallback(true);
    EXPECT_EQ(formBmsHelper.RegisterBundleEventCallback(), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_027 end";
}

/**
 * @tc.name: FmsFormBmsHelperTest_028
 * @tc.desc: Verify that the UnregisterBundleEventCallback interface executes normally and exits without exception.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormBmsHelperTest, FmsFormBmsHelperTest_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_028 start";
    FormBmsHelper formBmsHelper;
    const sptr<IRemoteObject> impl;
    const sptr<IBundleMgr> bundleManager = new (std::nothrow) MockBundleMgrProxy(impl);
    formBmsHelper.SetBundleManager(bundleManager);
    EXPECT_EQ(formBmsHelper.UnregisterBundleEventCallback(), ERR_APPEXECFWK_FORM_COMMON_CODE);

    MockUnregisterBundleEventCallback(true);
    EXPECT_EQ(formBmsHelper.UnregisterBundleEventCallback(), ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormHostRecordTest FmsFormBmsHelperTest_028 end";
}
} // namespace AppExecFwk
} // namespace OHOS
