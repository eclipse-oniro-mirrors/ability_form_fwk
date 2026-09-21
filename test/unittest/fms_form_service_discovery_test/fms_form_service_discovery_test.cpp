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
#include <cstring>
#include <string>
#include <vector>

#include "form_mgr_errors.h"
#include "form_service_constants.h"
#include "form_cross_device_constants.h"
#include "peer_form_service_info.h"
#include "form_service_info.h"

#define private public
#include "feature/service_discovery/form_service_discovery.h"
#include "feature/service_discovery/form_service_proxy.h"
#undef private

#include "inner/mock_dm_service_adapter.h"
#include "inner/mock_form_util.h"
#include "inner/mock_form_bms_helper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedHardware;

namespace {
constexpr int64_t TEST_SERVICE_ID = 100;
constexpr int32_t TEST_USER_ID = 100;
const std::string TEST_NETWORK_ID = "test-network-id-001";
const std::string TEST_UDID = "test-udid-12345678";
const std::string TEST_DEVICE_HASH = "device-hash-001";
const std::string TEST_BUNDLE_NAME = "com.test.bundle";

DmDeviceInfo MakeDeviceInfo(const std::string &networkId, DmAuthForm authForm)
{
    DmDeviceInfo dev;
    (void)memset_s(&dev, sizeof(dev), 0, sizeof(dev));
    (void)strncpy_s(dev.networkId, sizeof(dev.networkId), networkId.c_str(), sizeof(dev.networkId) - 1);
    (void)strncpy_s(dev.deviceId, sizeof(dev.deviceId), "dev-id", sizeof(dev.deviceId) - 1);
    (void)strncpy_s(dev.deviceName, sizeof(dev.deviceName), "dev-name", sizeof(dev.deviceName) - 1);
    dev.authForm = authForm;
    return dev;
}

DmServiceInfo MakeServiceInfo(const std::string &networkId, int64_t serviceId,
    const std::string &serviceType, DMPublishState publishState, DmAuthForm authForm)
{
    DmServiceInfo svc;
    svc.networkId = networkId;
    svc.serviceId = serviceId;
    svc.serviceType = serviceType;
    svc.publishState = publishState;
    svc.authform = authForm;
    svc.serviceName = "test-service";
    svc.serviceDisplayName = "TestServiceDisplayName";
    svc.displayId = 0;
    svc.customData = "{}";
    svc.deviceId = TEST_DEVICE_HASH;
    return svc;
}
} // namespace

class FmsFormServiceDiscoveryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void FmsFormServiceDiscoveryTest::SetUpTestCase()
{
    auto &discovery = FormServiceDiscovery::GetInstance();
    discovery.EnsureMembers();
}

void FmsFormServiceDiscoveryTest::TearDownTestCase() {}

void FmsFormServiceDiscoveryTest::SetUp()
{
    ResetDmServiceAdapterMock();
    MockGetCurrentAccountIdRet(TEST_USER_ID);
    MockGetCallerUserId(TEST_USER_ID);
    MockGetCallerBundleName(ERR_OK, TEST_BUNDLE_NAME);

    auto &discovery = FormServiceDiscovery::GetInstance();
    ServiceTransportHooks emptyHooks;
    discovery.serviceProxy_ = std::make_shared<FormServiceProxy>(discovery.dmAdapter_, emptyHooks);
    discovery.discoveredPeerKeys_.clear();
}

void FmsFormServiceDiscoveryTest::TearDown()
{
    auto &discovery = FormServiceDiscovery::GetInstance();
    discovery.discoveredPeerKeys_.clear();
}

/**
 * @tc.name: GetAvailableFormHostServices_001
 * @tc.desc: Verify GetAvailableFormHostServices when GetTrustedDeviceList fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetAvailableFormHostServices_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetTrustedDeviceList(-1, {});

    std::vector<PeerFormHostServiceInfo> services;
    ErrCode ret = discovery.GetAvailableFormHostServices(services);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SERVICE_DM_UNAVAILABLE);
    EXPECT_TRUE(services.empty());
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_001 end";
}

/**
 * @tc.name: GetAvailableFormHostServices_002
 * @tc.desc: Verify GetAvailableFormHostServices when GetTrustServiceInfo fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetAvailableFormHostServices_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetTrustedDeviceList(0, {MakeDeviceInfo(TEST_NETWORK_ID, DmAuthForm::IDENTICAL_ACCOUNT)});
    MockGetTrustServiceInfo(-1, {});

    std::vector<PeerFormHostServiceInfo> services;
    ErrCode ret = discovery.GetAvailableFormHostServices(services);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SERVICE_DM_UNAVAILABLE);
    EXPECT_TRUE(services.empty());
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_002 end";
}

/**
 * @tc.name: GetAvailableFormHostServices_003
 * @tc.desc: Verify GetAvailableFormHostServices when both DM calls succeed but no services returned.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetAvailableFormHostServices_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_003 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetTrustedDeviceList(0, {});
    MockGetTrustServiceInfo(0, {});

    std::vector<PeerFormHostServiceInfo> services;
    ErrCode ret = discovery.GetAvailableFormHostServices(services);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(services.empty());
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_003 end";
}

/**
 * @tc.name: GetAvailableFormHostServices_004
 * @tc.desc: Verify GetAvailableFormHostServices returns filtered peer services on success.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetAvailableFormHostServices_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_004 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetTrustedDeviceList(0, {MakeDeviceInfo(TEST_NETWORK_ID, DmAuthForm::IDENTICAL_ACCOUNT)});
    MockGetTrustServiceInfo(0, {
        MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
    });
    MockGetUdidByNetworkId(0, TEST_UDID);

    std::vector<PeerFormHostServiceInfo> services;
    ErrCode ret = discovery.GetAvailableFormHostServices(services);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(services.size(), 1u);
    EXPECT_EQ(services[0].networkId, TEST_NETWORK_ID);
    EXPECT_EQ(services[0].deviceId, TEST_UDID);
    GTEST_LOG_(INFO) << "GetAvailableFormHostServices_004 end";
}

/**
 * @tc.name: CollectIdenticalNetworkIds_001
 * @tc.desc: Verify CollectIdenticalNetworkIds with empty device list.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, CollectIdenticalNetworkIds_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    std::vector<DmDeviceInfo> devices;
    auto result = discovery.CollectIdenticalNetworkIds(devices);
    EXPECT_TRUE(result.empty());
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_001 end";
}

/**
 * @tc.name: CollectIdenticalNetworkIds_002
 * @tc.desc: Verify CollectIdenticalNetworkIds with no IDENTICAL_ACCOUNT devices.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, CollectIdenticalNetworkIds_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    auto nonIdentical = static_cast<DmAuthForm>(static_cast<int32_t>(DmAuthForm::IDENTICAL_ACCOUNT) + 1);
    std::vector<DmDeviceInfo> devices = {
        MakeDeviceInfo("net-1", nonIdentical),
        MakeDeviceInfo("net-2", nonIdentical),
    };
    auto result = discovery.CollectIdenticalNetworkIds(devices);
    EXPECT_TRUE(result.empty());
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_002 end";
}

/**
 * @tc.name: CollectIdenticalNetworkIds_003
 * @tc.desc: Verify CollectIdenticalNetworkIds when all devices are IDENTICAL_ACCOUNT.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, CollectIdenticalNetworkIds_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_003 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    std::vector<DmDeviceInfo> devices = {
        MakeDeviceInfo("net-1", DmAuthForm::IDENTICAL_ACCOUNT),
        MakeDeviceInfo("net-2", DmAuthForm::IDENTICAL_ACCOUNT),
    };
    auto result = discovery.CollectIdenticalNetworkIds(devices);
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result.count("net-1"), 1u);
    EXPECT_EQ(result.count("net-2"), 1u);
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_003 end";
}

/**
 * @tc.name: CollectIdenticalNetworkIds_004
 * @tc.desc: Verify CollectIdenticalNetworkIds with mixed authForm devices.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, CollectIdenticalNetworkIds_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_004 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    auto nonIdentical = static_cast<DmAuthForm>(static_cast<int32_t>(DmAuthForm::IDENTICAL_ACCOUNT) + 1);
    std::vector<DmDeviceInfo> devices = {
        MakeDeviceInfo("net-1", DmAuthForm::IDENTICAL_ACCOUNT),
        MakeDeviceInfo("net-2", nonIdentical),
        MakeDeviceInfo("net-3", DmAuthForm::IDENTICAL_ACCOUNT),
    };
    auto result = discovery.CollectIdenticalNetworkIds(devices);
    EXPECT_EQ(result.size(), 2u);
    EXPECT_EQ(result.count("net-1"), 1u);
    EXPECT_EQ(result.count("net-2"), 0u);
    EXPECT_EQ(result.count("net-3"), 1u);
    GTEST_LOG_(INFO) << "CollectIdenticalNetworkIds_004 end";
}

/**
 * @tc.name: FilterPeerServices_001
 * @tc.desc: Verify FilterPeerServices with empty dmServices list.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    std::vector<DmServiceInfo> dmServices;
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_TRUE(services.empty());
    EXPECT_TRUE(discovery.discoveredPeerKeys_.empty());
    GTEST_LOG_(INFO) << "FilterPeerServices_001 end";
}

/**
 * @tc.name: FilterPeerServices_002
 * @tc.desc: Verify FilterPeerServices skips non-FMS serviceType.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    std::vector<DmServiceInfo> dmServices = {
        MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, "other.service.type",
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
    };
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_TRUE(services.empty());
    EXPECT_TRUE(discovery.discoveredPeerKeys_.empty());
    GTEST_LOG_(INFO) << "FilterPeerServices_002 end";
}

/**
 * @tc.name: FilterPeerServices_003
 * @tc.desc: Verify FilterPeerServices skips unpublished services.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_003 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    auto unpublished = static_cast<DMPublishState>(static_cast<int32_t>(DMPublishState::SERVICE_PUBLISHED_STATE) + 1);
    std::vector<DmServiceInfo> dmServices = {
        MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
            unpublished, DmAuthForm::IDENTICAL_ACCOUNT),
    };
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_TRUE(services.empty());
    EXPECT_TRUE(discovery.discoveredPeerKeys_.empty());
    GTEST_LOG_(INFO) << "FilterPeerServices_003 end";
}

/**
 * @tc.name: FilterPeerServices_004
 * @tc.desc: Verify FilterPeerServices skips services not in identicalIds (offline or non-IDENTICAL_ACCOUNT).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_004 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    std::vector<DmServiceInfo> dmServices = {
        MakeServiceInfo("offline-net", TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
    };
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_TRUE(services.empty());
    EXPECT_TRUE(discovery.discoveredPeerKeys_.empty());
    GTEST_LOG_(INFO) << "FilterPeerServices_004 end";
}

/**
 * @tc.name: FilterPeerServices_005
 * @tc.desc: Verify FilterPeerServices adds matching service to result and discoveredPeerKeys_.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_005 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetUdidByNetworkId(0, TEST_UDID);
    std::vector<DmServiceInfo> dmServices = {
        MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
    };
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_EQ(services.size(), 1u);
    EXPECT_EQ(services[0].networkId, TEST_NETWORK_ID);
    EXPECT_EQ(services[0].serviceId, std::to_string(TEST_SERVICE_ID));
    EXPECT_EQ(services[0].deviceId, TEST_UDID);
    EXPECT_EQ(discovery.discoveredPeerKeys_.size(), 1u);
    EXPECT_EQ(discovery.discoveredPeerKeys_.count(TEST_NETWORK_ID + ":" + std::to_string(TEST_SERVICE_ID)), 1u);
    GTEST_LOG_(INFO) << "FilterPeerServices_005 end";
}

/**
 * @tc.name: FilterPeerServices_006
 * @tc.desc: Verify FilterPeerServices handles mixed services (some match, some skipped).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, FilterPeerServices_006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FilterPeerServices_006 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetUdidByNetworkId(0, TEST_UDID);
    auto nonIdentical = static_cast<DmAuthForm>(static_cast<int32_t>(DmAuthForm::IDENTICAL_ACCOUNT) + 1);
    std::vector<DmServiceInfo> dmServices = {
        MakeServiceInfo("net-other", 200, "other.type",
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
        MakeServiceInfo("net-unpub", 201, FORM_CD_SERVICE_TYPE,
            static_cast<DMPublishState>(static_cast<int32_t>(DMPublishState::SERVICE_PUBLISHED_STATE) + 1),
            DmAuthForm::IDENTICAL_ACCOUNT),
        MakeServiceInfo("net-offline", 202, FORM_CD_SERVICE_TYPE,
            DMPublishState::SERVICE_PUBLISHED_STATE, nonIdentical),
        MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
            DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT),
    };
    std::unordered_set<std::string> identicalIds = {TEST_NETWORK_ID};
    std::vector<PeerFormHostServiceInfo> services;

    discovery.FilterPeerServices(dmServices, identicalIds, services);
    EXPECT_EQ(services.size(), 1u);
    EXPECT_EQ(services[0].networkId, TEST_NETWORK_ID);
    EXPECT_EQ(discovery.discoveredPeerKeys_.size(), 1u);
    GTEST_LOG_(INFO) << "FilterPeerServices_006 end";
}

/**
 * @tc.name: TranslateDmServiceToPeer_001
 * @tc.desc: Verify TranslateDmServiceToPeer uses udid when GetUdidByNetworkId succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, TranslateDmServiceToPeer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetUdidByNetworkId(0, TEST_UDID);
    DmServiceInfo dmSvc = MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
        DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT);

    PeerFormHostServiceInfo peerInfo;
    discovery.TranslateDmServiceToPeer(dmSvc, peerInfo);
    EXPECT_EQ(peerInfo.deviceId, TEST_UDID);
    EXPECT_EQ(peerInfo.networkId, TEST_NETWORK_ID);
    EXPECT_EQ(peerInfo.serviceId, std::to_string(TEST_SERVICE_ID));
    EXPECT_EQ(peerInfo.serviceName, "test-service");
    EXPECT_EQ(peerInfo.serviceDisplayName, "TestServiceDisplayName");
    EXPECT_EQ(peerInfo.displayId, "0");
    EXPECT_EQ(peerInfo.customData, "{}");
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_001 end";
}

/**
 * @tc.name: TranslateDmServiceToPeer_002
 * @tc.desc: Verify TranslateDmServiceToPeer falls back to dmSvc.deviceId when GetUdidByNetworkId fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, TranslateDmServiceToPeer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetUdidByNetworkId(-1, "");
    DmServiceInfo dmSvc = MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
        DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT);

    PeerFormHostServiceInfo peerInfo;
    discovery.TranslateDmServiceToPeer(dmSvc, peerInfo);
    EXPECT_EQ(peerInfo.deviceId, TEST_DEVICE_HASH);
    EXPECT_EQ(peerInfo.networkId, TEST_NETWORK_ID);
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_002 end";
}

/**
 * @tc.name: TranslateDmServiceToPeer_003
 * @tc.desc: Verify TranslateDmServiceToPeer falls back when GetUdidByNetworkId succeeds but udid is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, TranslateDmServiceToPeer_003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_003 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    MockGetUdidByNetworkId(0, "");
    DmServiceInfo dmSvc = MakeServiceInfo(TEST_NETWORK_ID, TEST_SERVICE_ID, FORM_CD_SERVICE_TYPE,
        DMPublishState::SERVICE_PUBLISHED_STATE, DmAuthForm::IDENTICAL_ACCOUNT);

    PeerFormHostServiceInfo peerInfo;
    discovery.TranslateDmServiceToPeer(dmSvc, peerInfo);
    EXPECT_EQ(peerInfo.deviceId, TEST_DEVICE_HASH);
    GTEST_LOG_(INFO) << "TranslateDmServiceToPeer_003 end";
}

/**
 * @tc.name: IsDiscoveredPeer_001
 * @tc.desc: Verify IsDiscoveredPeer returns true when peer key exists in discoveredPeerKeys_.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, IsDiscoveredPeer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsDiscoveredPeer_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    discovery.discoveredPeerKeys_.insert(TEST_NETWORK_ID + ":" + std::to_string(TEST_SERVICE_ID));
    EXPECT_TRUE(discovery.IsDiscoveredPeer(TEST_NETWORK_ID, TEST_SERVICE_ID));
    GTEST_LOG_(INFO) << "IsDiscoveredPeer_001 end";
}

/**
 * @tc.name: IsDiscoveredPeer_002
 * @tc.desc: Verify IsDiscoveredPeer returns false when peer key does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, IsDiscoveredPeer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsDiscoveredPeer_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    discovery.discoveredPeerKeys_.clear();
    EXPECT_FALSE(discovery.IsDiscoveredPeer(TEST_NETWORK_ID, TEST_SERVICE_ID));
    EXPECT_FALSE(discovery.IsDiscoveredPeer("nonexistent-net", 999));
    GTEST_LOG_(INFO) << "IsDiscoveredPeer_002 end";
}

/**
 * @tc.name: Dump_001
 * @tc.desc: Verify Dump outputs header only when serviceProxy_ is null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, Dump_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "Dump_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    auto savedProxy = discovery.serviceProxy_;
    discovery.serviceProxy_ = nullptr;

    std::string result;
    discovery.Dump(result);
    EXPECT_NE(result.find("== FormService =="), std::string::npos);
    EXPECT_EQ(result.find("registered:"), std::string::npos);

    discovery.serviceProxy_ = savedProxy;
    GTEST_LOG_(INFO) << "Dump_001 end";
}

/**
 * @tc.name: Dump_002
 * @tc.desc: Verify Dump outputs header and proxy info when serviceProxy_ is non-null.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, Dump_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Dump_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    ASSERT_NE(discovery.serviceProxy_, nullptr);

    std::string result;
    discovery.Dump(result);
    EXPECT_NE(result.find("== FormService =="), std::string::npos);
    EXPECT_NE(result.find("registered:"), std::string::npos);
    GTEST_LOG_(INFO) << "Dump_002 end";
}

/**
 * @tc.name: GetUserIdByServiceId_001
 * @tc.desc: Verify GetUserIdByServiceId returns true and correct userId when service exists.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetUserIdByServiceId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    ASSERT_NE(discovery.serviceProxy_, nullptr);

    std::string key = TEST_BUNDLE_NAME + "|" + std::to_string(TEST_USER_ID);
    FormServiceProxy::LocalEntry entry;
    entry.serviceId = TEST_SERVICE_ID;
    entry.info.userId = TEST_USER_ID;
    discovery.serviceProxy_->localEntries_[key] = std::move(entry);
    discovery.serviceProxy_->serviceIdToKey_[TEST_SERVICE_ID] = key;

    int32_t userId = -1;
    bool ret = discovery.GetUserIdByServiceId(TEST_SERVICE_ID, userId);
    EXPECT_TRUE(ret);
    EXPECT_EQ(userId, TEST_USER_ID);
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_001 end";
}

/**
 * @tc.name: GetUserIdByServiceId_002
 * @tc.desc: Verify GetUserIdByServiceId returns false when service does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, GetUserIdByServiceId_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_002 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    ASSERT_NE(discovery.serviceProxy_, nullptr);
    discovery.serviceProxy_->localEntries_.clear();
    discovery.serviceProxy_->serviceIdToKey_.clear();

    int32_t userId = -1;
    bool ret = discovery.GetUserIdByServiceId(TEST_SERVICE_ID + 999, userId);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "GetUserIdByServiceId_002 end";
}

/**
 * @tc.name: Register_001
 * @tc.desc: Verify Register returns ERR_APPEXECFWK_FORM_INVALID_PARAM when serviceName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, Register_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Register_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    FormHostServiceInfo info;
    info.serviceName = "";
    info.serviceDisplayName = "ValidDisplayName";

    int64_t serviceId = -1;
    ErrCode ret = discovery.Register(info, serviceId);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "Register_001 end";
}

/**
 * @tc.name: Unregister_001
 * @tc.desc: Verify Unregister returns ERR_APPEXECFWK_FORM_SERVICE_NOT_EXIST when service not registered.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormServiceDiscoveryTest, Unregister_001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "Unregister_001 start";
    auto &discovery = FormServiceDiscovery::GetInstance();
    ASSERT_NE(discovery.serviceProxy_, nullptr);
    discovery.serviceProxy_->localEntries_.clear();
    discovery.serviceProxy_->serviceIdToKey_.clear();

    ErrCode ret = discovery.Unregister(TEST_SERVICE_ID);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_SERVICE_NOT_EXIST);
    GTEST_LOG_(INFO) << "Unregister_001 end";
}
