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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#define private public
#define protected public
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_mgr_errors.h"
#include "form_mgr_interface.h"
#include "form_constants.h"
#include "form_router_proxy_mgr.h"
#include "form_supply_interface.h"
#include "form_supply_stub.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "mock_form_provider_client.h"
#undef public
#undef protected
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormRouterProxyMgrTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRouterProxyMgrTest::SetUpTestCase()
{}

void FormRouterProxyMgrTest::TearDownTestCase()
{}

void FormRouterProxyMgrTest::SetUp()
{}

void FormRouterProxyMgrTest::TearDown()
{}

/**
 * @tc.number: FormRouterProxyMgrTest_001
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the SetDeathRecipient interface is called normally
 * and the formRouterProxyMap size is 1.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_001 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    auto dealthRecipient = new (std::nothrow) FormRouterProxyMgr::ClientDeathRecipient();
    formRouterProxyMgr.SetDeathRecipient(callerToken, dealthRecipient);
    EXPECT_EQ(1, formRouterProxyMgr.deathRecipients_.size());
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_001 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_002
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the SetFormRouterProxy interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_002 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    auto ret = formRouterProxyMgr.SetFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_002 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_003
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the SetFormRouterProxy interface is called normally
 * and the formRouterProxyMap_ size is 1.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_003 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formRouterProxyMgr.SetFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(1, formRouterProxyMgr.formRouterProxyMap_.size());
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_003 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_004
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the RemoveFormRouterProxy interface is called normally
 * and the return value size is ERR_OK.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_004 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    auto ret = formRouterProxyMgr.RemoveFormRouterProxy(formIds);
    EXPECT_EQ(ERR_OK, ret);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_004 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_005
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the RemoveFormRouterProxy interface is called normally
 * and the formRouterProxyMap_ size is 0.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_005 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    formRouterProxyMgr.RemoveFormRouterProxy(formIds);
    EXPECT_EQ(0, formRouterProxyMgr.formRouterProxyMap_.size());
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_005 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_006
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the HasRouterProxy interface is called normally
 * and the return value is true.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_006 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formRouterProxyMgr.SetFormRouterProxy(formIds, callerToken);
    auto ret = formRouterProxyMgr.HasRouterProxy(formId);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_006 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_007
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the HasRouterProxy interface is called normally
 * and the return value is false.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_007 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formIdNoRegister = 0;
    auto ret = formRouterProxyMgr.HasRouterProxy(formIdNoRegister);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_007 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_008
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the OnFormRouterEvent interface is called normally
 * and the formRouterProxyMap_[formId] value is 0.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_008 start";
    FormRouterProxyMgr formRouterProxyMgr;
    int64_t formIdNoRegister = 0;
    Want want;
    formRouterProxyMgr.OnFormRouterEvent(formIdNoRegister, want);
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    formRouterProxyMgr.formRouterProxyMap_.emplace(formId, nullptr);
    formRouterProxyMgr.OnFormRouterEvent(formId, want);
    EXPECT_EQ(NULL, formRouterProxyMgr.formRouterProxyMap_[formId]);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_008 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_009
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the OnFormRouterEvent interface is called normally
 * and the formRouterProxyMap_[formId] value is setted callerToken.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_009 start";
    FormRouterProxyMgr formRouterProxyMgr;
    Want want;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formRouterProxyMgr.SetFormRouterProxy(formIds, callerToken);
    formRouterProxyMgr.OnFormRouterEvent(formId, want);
    EXPECT_EQ(callerToken, formRouterProxyMgr.formRouterProxyMap_[formId]);
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_009 end";
}

/**
 * @tc.number: FormRouterProxyMgrTest_010
 * @tc.name: FormRouterProxyMgrTest
 * @tc.desc: Verify that the CleanResource interface is called normally
 * and the formRouterProxyMap_ size is 0.
 */
HWTEST_F(FormRouterProxyMgrTest, FormRouterProxyMgrTest_010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_010 start";
    FormRouterProxyMgr formRouterProxyMgr;
    formRouterProxyMgr.CleanResource(nullptr);

    int64_t formId = 1;
    wptr<IRemoteObject> object = new (std::nothrow) MockFormProviderClient();
    auto callerToken = object.promote();
    formRouterProxyMgr.formRouterProxyMap_.emplace(formId, callerToken);
    formRouterProxyMgr.CleanResource(object);
    EXPECT_EQ(0, formRouterProxyMgr.formRouterProxyMap_.size());
    GTEST_LOG_(INFO) << "FormRouterProxyMgrTest_010 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
