/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "appexecfwk_errors.h"
#define private public
#define protected public
#include "form_mgr_proxy.h"
#undef private
#undef protected
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace std::placeholders;

extern void MockWriteInterfaceToken(bool mockRet);

namespace {
class FmsFormMgrProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormMgrProxyTest::SetUpTestCase() {}
void FmsFormMgrProxyTest::TearDownTestCase() {}
void FmsFormMgrProxyTest::SetUp()
{
    MockWriteInterfaceToken(true);
}
void FmsFormMgrProxyTest::TearDown() {}

int SendRequestReplace(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError)
{
    if (setError) {
        reply.WriteInt32(error);
    }
    return 0;
}

int SendRequestReplaceFormData(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    AAFwk::WantParams params;
    reply.WriteParcelable(&params);
    return 0;
}

int SendRequestReplaceFormInfo(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option,
    int32_t error, bool setError, int32_t num)
{
    if (setError) {
        reply.WriteInt32(error);
    }

    reply.WriteInt32(num);
    for (int32_t i = 0; i < num; i++) {
        FormInfo info;
        reply.WriteParcelable(&info);
    }

    return 0;
}

/*
 * @tc.name: AddFormTest_0100
 * @tc.desc: test AddForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AddFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AddFormTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    MockWriteInterfaceToken(false);
    Want want;
    FormJsInfo formInfo;
    int32_t result = proxy->AddForm(0, want, nullptr, formInfo);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: AddFormTest_0200
 * @tc.desc: test AddForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AddFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AddFormTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    FormJsInfo formInfo;
    int32_t result = proxy->AddForm(0, want, nullptr, formInfo);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DeleteFormTest_0100
 * @tc.desc: test DeleteForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteForm(0, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DeleteFormTest_0200
 * @tc.desc: test DeleteForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteForm(0, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: DeleteFormTest_0300
 * @tc.desc: test DeleteForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->DeleteForm(0, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: ReleaseFormTest_0100
 * @tc.desc: test ReleaseForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ReleaseFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ReleaseFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->ReleaseForm(0, nullptr, true);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: ReleaseFormTest_0200
 * @tc.desc: test ReleaseForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ReleaseFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ReleaseFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->ReleaseForm(0, nullptr, true);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: ReleaseFormTest_0300
 * @tc.desc: test ReleaseForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ReleaseFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ReleaseFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->ReleaseForm(0, nullptr, true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: UpdateFormTest_0100
 * @tc.desc: test UpdateForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UpdateFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, UpdateFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormProviderData FormProviderData;
    int32_t result = proxy->UpdateForm(0, FormProviderData);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: UpdateFormTest_0200
 * @tc.desc: test UpdateForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UpdateFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, UpdateFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormProviderData FormProviderData;
    int32_t result = proxy->UpdateForm(0, FormProviderData);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: UpdateFormTest_0300
 * @tc.desc: test UpdateForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UpdateFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, UpdateFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormProviderData FormProviderData;
    int32_t result = proxy->UpdateForm(0, FormProviderData);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: SetNextRefreshTimeTest_0100
 * @tc.desc: test SetNextRefreshTime function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetNextRefreshTimeTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, SetNextRefreshTimeTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNextRefreshTime(0, 0);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: SetNextRefreshTimeTest_0200
 * @tc.desc: test SetNextRefreshTime function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetNextRefreshTimeTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, SetNextRefreshTimeTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNextRefreshTime(0, 0);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: SetNextRefreshTimeTest_0300
 * @tc.desc: test SetNextRefreshTime function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetNextRefreshTimeTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, SetNextRefreshTimeTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->SetNextRefreshTime(0, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: LifecycleUpdateTest_0100
 * @tc.desc: test LifecycleUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, LifecycleUpdateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, LifecycleUpdateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->LifecycleUpdate(formIds, nullptr, true);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: LifecycleUpdateTest_0200
 * @tc.desc: test LifecycleUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, LifecycleUpdateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, LifecycleUpdateTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->LifecycleUpdate(formIds, nullptr, true);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: LifecycleUpdateTest_0300
 * @tc.desc: test LifecycleUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, LifecycleUpdateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, LifecycleUpdateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->LifecycleUpdate(formIds, nullptr, true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: RequestFormTest_0100
 * @tc.desc: test RequestForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RequestForm(0, nullptr, want);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RequestFormTest_0200
 * @tc.desc: test RequestForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RequestForm(0, nullptr, want);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RequestFormTest_0300
 * @tc.desc: test RequestForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RequestForm(0, nullptr, want);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: NotifyWhetherVisibleFormsTest_0100
 * @tc.desc: test NotifyWhetherVisibleForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyWhetherVisibleForms(formIds, nullptr, 0);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: NotifyWhetherVisibleFormsTest_0200
 * @tc.desc: test NotifyWhetherVisibleForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyWhetherVisibleForms(formIds, nullptr, 0);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: NotifyWhetherVisibleFormsTest_0300
 * @tc.desc: test NotifyWhetherVisibleForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyWhetherVisibleFormsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyWhetherVisibleForms(formIds, nullptr, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: CastTempFormTest_0100
 * @tc.desc: test CastTempForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, CastTempFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, CastTempFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CastTempForm(0, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: CastTempFormTest_0200
 * @tc.desc: test CastTempForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, CastTempFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, CastTempFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CastTempForm(0, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: CastTempFormTest_0300
 * @tc.desc: test CastTempForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, CastTempFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, CastTempFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t result = proxy->CastTempForm(0, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: MessageEventTest_0100
 * @tc.desc: test MessageEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, MessageEventTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, MessageEventTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->MessageEvent(0, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: MessageEventTest_0200
 * @tc.desc: test MessageEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, MessageEventTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, MessageEventTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->MessageEvent(0, want, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: MessageEventTest_0300
 * @tc.desc: test MessageEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, MessageEventTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, MessageEventTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->MessageEvent(0, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: RouterEventTest_0100
 * @tc.desc: test RouterEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RouterEventTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RouterEventTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RouterEvent(0, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RouterEventTest_0200
 * @tc.desc: test RouterEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RouterEventTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RouterEventTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RouterEvent(0, want, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RouterEventTest_0300
 * @tc.desc: test RouterEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RouterEventTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RouterEventTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->RouterEvent(0, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: DeleteInvalidFormsTest_0100
 * @tc.desc: test DeleteInvalidForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteInvalidFormsTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteInvalidFormsTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t numFormsDeleted = 0;
    int32_t result = proxy->DeleteInvalidForms(formIds, nullptr, numFormsDeleted);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DeleteInvalidFormsTest_0200
 * @tc.desc: test DeleteInvalidForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteInvalidFormsTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteInvalidFormsTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t numFormsDeleted = 0;
    int32_t result = proxy->DeleteInvalidForms(formIds, nullptr, numFormsDeleted);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: DeleteInvalidFormsTest_0300
 * @tc.desc: test DeleteInvalidForms function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DeleteInvalidFormsTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DeleteInvalidFormsTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t numFormsDeleted = 0;
    int32_t result = proxy->DeleteInvalidForms(formIds, nullptr, numFormsDeleted);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: AcquireFormStateTest_0100
 * @tc.desc: test AcquireFormState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormStateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormStateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    FormStateInfo stateInfo;
    int32_t result = proxy->AcquireFormState(want, nullptr, stateInfo);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: AcquireFormStateTest_0200
 * @tc.desc: test AcquireFormState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormStateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormStateTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    FormStateInfo stateInfo;
    int32_t result = proxy->AcquireFormState(want, nullptr, stateInfo);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: AcquireFormStateTest_0300
 * @tc.desc: test AcquireFormState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormStateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormStateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    FormStateInfo stateInfo;
    int32_t result = proxy->AcquireFormState(want, nullptr, stateInfo);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: NotifyFormsVisibleTest_0100
 * @tc.desc: test NotifyFormsVisible function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsVisibleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsVisibleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsVisible(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: NotifyFormsVisibleTest_0200
 * @tc.desc: test NotifyFormsVisible function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsVisibleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsVisibleTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsVisible(formIds, true, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: NotifyFormsVisibleTest_0300
 * @tc.desc: test NotifyFormsVisible function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsVisibleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsVisibleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsVisible(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: NotifyFormsPrivacyProtectedTest_0100
 * @tc.desc: test NotifyFormsPrivacyProtected function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsPrivacyProtected(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: NotifyFormsPrivacyProtectedTest_0200
 * @tc.desc: test NotifyFormsPrivacyProtected function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsPrivacyProtected(formIds, true, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: NotifyFormsPrivacyProtectedTest_0300
 * @tc.desc: test NotifyFormsPrivacyProtected function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsPrivacyProtectedTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsPrivacyProtected(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: NotifyFormsEnableUpdateTest_0100
 * @tc.desc: test NotifyFormsEnableUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsEnableUpdate(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: NotifyFormsEnableUpdateTest_0200
 * @tc.desc: test NotifyFormsEnableUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsEnableUpdate(formIds, true, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: NotifyFormsEnableUpdateTest_0300
 * @tc.desc: test NotifyFormsEnableUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, NotifyFormsEnableUpdateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    int32_t result = proxy->NotifyFormsEnableUpdate(formIds, true, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetAllFormsInfoTest_0100
 * @tc.desc: test GetAllFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetAllFormsInfoTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetAllFormsInfoTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetAllFormsInfo(formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetAllFormsInfoTest_0200
 * @tc.desc: test GetAllFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetAllFormsInfoTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetAllFormsInfoTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetAllFormsInfo(formInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, formInfos.size());
}

/*
 * @tc.name: GetAllFormsInfoTest_0300
 * @tc.desc: test GetAllFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetAllFormsInfoTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetAllFormsInfoTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetAllFormsInfo(formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormsInfoByAppTest_0100
 * @tc.desc: test GetFormsInfoByApp function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByAppTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByAppTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    int32_t result = proxy->GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetFormsInfoByAppTest_0200
 * @tc.desc: test GetFormsInfoByApp function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByAppTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByAppTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    int32_t result = proxy->GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, formInfos.size());
}

/*
 * @tc.name: GetFormsInfoByAppTest_0300
 * @tc.desc: test GetFormsInfoByApp function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByAppTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByAppTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    int32_t result = proxy->GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormsInfoByModuleTest_0100
 * @tc.desc: test GetFormsInfoByModule function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    std::string moduleName = "ModuleName";
    int32_t result = proxy->GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetFormsInfoByModuleTest_0200
 * @tc.desc: test GetFormsInfoByModule function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    std::string moduleName = "ModuleName";
    int32_t result = proxy->GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, formInfos.size());
}

/*
 * @tc.name: GetFormsInfoByModuleTest_0300
 * @tc.desc: test GetFormsInfoByModule function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByModuleTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    std::string bundleName = "BundleName";
    std::string moduleName = "ModuleName";
    int32_t result = proxy->GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormsInfoTest_0100
 * @tc.desc: test GetFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetFormsInfo(filter, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetFormsInfoTest_0200
 * @tc.desc: test GetFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetFormsInfo(filter, formInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, formInfos.size());
}

/*
 * @tc.name: GetFormsInfoTest_0300
 * @tc.desc: test GetFormsInfo function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    int32_t result = proxy->GetFormsInfo(filter, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: IsRequestPublishFormSupportedTest_0100
 * @tc.desc: test IsRequestPublishFormSupported function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool result = proxy->IsRequestPublishFormSupported();
    EXPECT_EQ(false, result);
}

/*
 * @tc.name: IsRequestPublishFormSupportedTest_0200
 * @tc.desc: test IsRequestPublishFormSupported function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool result = proxy->IsRequestPublishFormSupported();
    EXPECT_EQ(false, result);
}

/*
 * @tc.name: IsRequestPublishFormSupportedTest_0300
 * @tc.desc: test IsRequestPublishFormSupported function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, IsRequestPublishFormSupportedTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    bool result = proxy->IsRequestPublishFormSupported();
    EXPECT_EQ(false, result);
}

/*
 * @tc.name: StartAbilityTest_0100
 * @tc.desc: test StartAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, StartAbilityTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, StartAbilityTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->StartAbility(want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: StartAbilityTest_0200
 * @tc.desc: test StartAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, StartAbilityTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, StartAbilityTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->StartAbility(want, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: StartAbilityTest_0300
 * @tc.desc: test StartAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, StartAbilityTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, StartAbilityTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    int32_t result = proxy->StartAbility(want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: ShareFormTest_0100
 * @tc.desc: test ShareForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ShareFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ShareFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "DeviceId";
    int32_t result = proxy->ShareForm(0, deviceId, nullptr, 0);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: ShareFormTest_0200
 * @tc.desc: test ShareForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ShareFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ShareFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "DeviceId";
    int32_t result = proxy->ShareForm(0, deviceId, nullptr, 0);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: ShareFormTest_0300
 * @tc.desc: test ShareForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ShareFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ShareFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string deviceId = "DeviceId";
    int32_t result = proxy->ShareForm(0, deviceId, nullptr, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: RecvFormShareInfoFromRemoteTest_0100
 * @tc.desc: test RecvFormShareInfoFromRemote function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormShareInfo info;
    int32_t result = proxy->RecvFormShareInfoFromRemote(info);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RecvFormShareInfoFromRemoteTest_0200
 * @tc.desc: test RecvFormShareInfoFromRemote function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormShareInfo info;
    int32_t result = proxy->RecvFormShareInfoFromRemote(info);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RecvFormShareInfoFromRemoteTest_0300
 * @tc.desc: test RecvFormShareInfoFromRemote function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RecvFormShareInfoFromRemoteTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormShareInfo info;
    int32_t result = proxy->RecvFormShareInfoFromRemote(info);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: RequestPublishFormTest_0100
 * @tc.desc: test RequestPublishForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RequestPublishFormTest_0200
 * @tc.desc: test RequestPublishForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RequestPublishFormTest_0300
 * @tc.desc: test RequestPublishForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = false;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishForm(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: SendTransactCmdTest_0100
 * @tc.desc: test SendTransactCmd function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SendTransactCmdTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, SendTransactCmdTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    IFormMgr::Message code = IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = proxy->SendTransactCmd(code, data, reply, option);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: SendTransactCmdTest_0200
 * @tc.desc: test SendTransactCmd function and return ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SendTransactCmdTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, SendTransactCmdTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    IFormMgr::Message code = IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = proxy->SendTransactCmd(code, data, reply, option);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetStringInfoTest_0100
 * @tc.desc: test GetStringInfo function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetStringInfoTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetStringInfoTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    IFormMgr::Message code = IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID;
    MessageParcel data;
    std::string stringInfo = "<stringInfo>";
    int32_t result = proxy->GetStringInfo(code, data, stringInfo);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetStringInfoTest_0200
 * @tc.desc: test GetStringInfo function and return ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetStringInfoTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetStringInfoTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    IFormMgr::Message code = IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID;
    MessageParcel data;
    std::string stringInfo = "<stringInfo>";
    int32_t result = proxy->GetStringInfo(code, data, stringInfo);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, result);
}

/*
 * @tc.name: DumpStorageFormInfosTest_0100
 * @tc.desc: test DumpStorageFormInfos function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpStorageFormInfosTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpStorageFormInfosTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string formInfos = "<formInfos>";
    int32_t result = proxy->DumpStorageFormInfos(formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DumpStorageFormInfosTest_0200
 * @tc.desc: test DumpStorageFormInfos function and return ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpStorageFormInfosTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpStorageFormInfosTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string formInfos = "<formInfos>";
    int32_t result = proxy->DumpStorageFormInfos(formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, result);
}

/*
 * @tc.name: DumpFormInfoByBundleNameTest_0100
 * @tc.desc: test DumpFormInfoByBundleName function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormInfoByBundleNameTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormInfoByBundleNameTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string bundleName = "<bundleName>";
    std::string formInfos = "<formInfos>";
    int32_t result = proxy->DumpFormInfoByBundleName(bundleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DumpFormInfoByBundleNameTest_0200
 * @tc.desc: test DumpFormInfoByBundleName function and return ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormInfoByBundleNameTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormInfoByBundleNameTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string bundleName = "<bundleName>";
    std::string formInfos = "<formInfos>";
    int32_t result = proxy->DumpFormInfoByBundleName(bundleName, formInfos);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, result);
}

/*
 * @tc.name: DumpFormInfoByFormIdTest_0100
 * @tc.desc: test DumpFormInfoByFormId function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormInfoByFormIdTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormInfoByFormIdTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::int64_t formId = 1;
    std::string formInfo = "<formInfo>";
    int32_t result = proxy->DumpFormInfoByFormId(formId, formInfo);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DumpFormInfoByFormIdTest_0200
 * @tc.desc: test DumpFormInfoByFormId function and return ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormInfoByFormIdTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormInfoByFormIdTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::int64_t formId = 1;
    std::string formInfo = "<formInfo>";
    int32_t result = proxy->DumpFormInfoByFormId(formId, formInfo);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, result);
}

/*
 * @tc.name: DumpFormTimerByFormIdTest_0100
 * @tc.desc: test DumpFormTimerByFormId function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormTimerByFormIdTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormTimerByFormIdTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::int64_t formId = 1;
    std::string isTimingService = "<isTimingService>";
    int32_t result = proxy->DumpFormTimerByFormId(formId, isTimingService);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: DumpFormTimerByFormIdTest_0200
 * @tc.desc: test DumpFormTimerByFormId function and return ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, DumpFormTimerByFormIdTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, DumpFormTimerByFormIdTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::int64_t formId = 1;
    std::string isTimingService = "<isTimingService>";
    int32_t result = proxy->DumpFormTimerByFormId(formId, isTimingService);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, result);
}

/*
 * @tc.name: BackgroundEventTest_0100
 * @tc.desc: test BackgroundEvent function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, BackgroundEventTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, BackgroundEventTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Want want;
    int32_t result = proxy->BackgroundEvent(formId, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: BackgroundEventTest_0200
 * @tc.desc: test BackgroundEvent function and return ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, BackgroundEventTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, BackgroundEventTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Want want;
    int32_t result = proxy->BackgroundEvent(formId, want, nullptr);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: BackgroundEventTest_0300
 * @tc.desc: test BackgroundEvent function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, BackgroundEventTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, BackgroundEventTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Want want;
    int32_t result = proxy->BackgroundEvent(formId, want, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormsCountTest_0100
 * @tc.desc: test GetFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsCountTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsCountTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t count;
    int32_t result = proxy->GetFormsCount(true, count);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetFormsCountTest_0200
 * @tc.desc: test GetFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsCountTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsCountTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t count;
    int32_t result = proxy->GetFormsCount(true, count);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetFormsCountTest_0300
 * @tc.desc: test GetFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsCountTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsCountTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int32_t count;
    int32_t result = proxy->GetFormsCount(true, count);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetHostFormsCount_0100
 * @tc.desc: test GetHostFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetHostFormsCount_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetHostFormsCount_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string bundleName = "BundleName";
    int count;
    int32_t result = proxy->GetHostFormsCount(bundleName, count);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: GetHostFormsCount_0200
 * @tc.desc: test GetHostFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetHostFormsCount_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetHostFormsCount_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string bundleName = "BundleName";
    int32_t count;
    int32_t result = proxy->GetHostFormsCount(bundleName, count);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: GetHostFormsCount_0300
 * @tc.desc: test GetHostFormsCount function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetHostFormsCount_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetHostFormsCount_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::string bundleName = "BundleName";
    int32_t count;
    int32_t result = proxy->GetHostFormsCount(bundleName, count);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}


/*
 * @tc.name: AcquireFormDataTest_0100
 * @tc.desc: test AcquireFormData function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormDataTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormDataTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    AAFwk::WantParams formData;
    int32_t result = proxy->AcquireFormData(formId, 0, nullptr, formData);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: AcquireFormData_0200
 * @tc.desc: test AcquireFormData function and return ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormData_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormData_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormData, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    AAFwk::WantParams formData;
    int32_t result = proxy->AcquireFormData(formId, 0, nullptr, formData);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: AcquireFormData_0300
 * @tc.desc: test AcquireFormData function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, AcquireFormData_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, AcquireFormData_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    AAFwk::WantParams formData;
    int32_t result = proxy->AcquireFormData(formId, 0, nullptr, formData);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormInstancesByFilter_0100
 * @tc.desc: test GetFormInstancesByFilter function and return ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstancesByFilter_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstancesByFilter_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(0)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    int32_t result = proxy->GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * @tc.name: GetFormInstancesByFilter_0200
 * @tc.desc: test GetFormInstancesByFilter function and return ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstancesByFilter_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstancesByFilter_0200, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    int32_t result = proxy->GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/*
 * @tc.name: GetFormInstancesByFilter_0300
 * @tc.desc: test GetFormInstancesByFilter function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstancesByFilter_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstancesByFilter_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInstancesFilter formInstancesFilter;
    std::vector<FormInstance> formInstances;
    int32_t result = proxy->GetFormInstancesByFilter(formInstancesFilter, formInstances);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);
}

/*
 * @tc.name: GetFormInstancesById_0100
 * @tc.desc: test GetFormInstancesById function and return ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstancesById_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstancesById_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(0)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInstance formInstance;
    int32_t result = proxy->GetFormInstanceById(0, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/*
 * @tc.name: GetFormInstancesById_0200
 * @tc.desc: test GetFormInstancesById function and return ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstancesById_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstancesById_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormInstance formInstance;
    int32_t result = proxy->GetFormInstanceById(0, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/*
 * @tc.name: GetFormInstance_0100
 * @tc.desc: test GetFormInstance function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstance_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstance_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(0)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInstance> formInstance;
    MessageParcel data;
    int32_t result =
        proxy->GetFormInstance(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID, data, formInstance);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * @tc.name: GetFormInstance_0200
 * @tc.desc: test GetFormInstance function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormInstance_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, GetFormInstance_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInstance> formInstance;
    MessageParcel data;
    int32_t result =
        proxy->GetFormInstance(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID, data, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);
}

/*
 * @tc.name: GetFormsInfoByFilterTest_0201
 * @tc.desc: test GetFormsInfoByFilter function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormsInfoByFilterTest_0201, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormsInfoByFilterTest_0201, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplaceFormInfo, _1, _2, _3, _4,
        ERR_OK, true, 1)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    int32_t result = proxy->GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_EQ(1, formInfos.size());
}

/*
 * @tc.name: StopRenderingForm_0100
 * @tc.desc: test StopRenderingForm function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, StopRenderingForm_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, StopRenderingForm_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    std::string compId = "1";
    int32_t result = proxy->StopRenderingForm(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, StopRenderingForm_0100, end";
}

/*
 * @tc.name: ReleaseRenderer_0100
 * @tc.desc: test ReleaseRenderer function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ReleaseRenderer_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, ReleaseRenderer_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    std::string compId = "1";
    int32_t result = proxy->ReleaseRenderer(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, ReleaseRenderer_0100, end";
}

/*
 * @tc.name: CheckFMSReady_0100
 * @tc.desc: test CheckFMSReady function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, CheckFMSReady_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, CheckFMSReady_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t result = proxy->CheckFMSReady();
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, CheckFMSReady_0100, end";
}

/*
 * @tc.name: SetBackgroundFunction_0100
 * @tc.desc: test SetBackgroundFunction function and return ERR_APPEXECFWK_FORM_SEND_FMS_MSG
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetBackgroundFunction_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetBackgroundFunction_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::string funcName = "1";
    std::string params = "1";
    int32_t result = proxy->SetBackgroundFunction(funcName, params);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetBackgroundFunction_0100, end";
}

/*
 * @tc.name: UpdateProxyForm_0100
 * @tc.desc: test UpdateProxyForm function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UpdateProxyForm_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UpdateProxyForm_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int64_t formId = 1;
    FormProviderData FormProviderData;
    std::vector<FormDataProxy> formDataProxies;
    int32_t result = proxy->UpdateProxyForm(formId, FormProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UpdateProxyForm_0100, end";
}

/*
 * @tc.name: UpdateProxyForm_0200
 * @tc.desc: test UpdateProxyForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UpdateProxyForm_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UpdateProxyForm_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int64_t formId = 1;
    FormProviderData FormProviderData;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    int32_t result = proxy->UpdateProxyForm(formId, FormProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UpdateProxyForm_0200, end";
}

/*
 * @tc.name: RequestPublishProxyForm_0100
 * @tc.desc: test RequestPublishProxyForm function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishProxyForm_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RequestPublishProxyForm_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formProviderData;
    int64_t formId = 0;
    std::vector<FormDataProxy> formDataProxies;
    int32_t result = proxy->RequestPublishProxyForm(want, withFormBindingData, formProviderData,
                                                    formId, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RequestPublishProxyForm_0100, end";
}

/*
 * @tc.name: RequestPublishProxyForm_0200
 * @tc.desc: test RequestPublishProxyForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishProxyForm_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RequestPublishProxyForm_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formProviderData;
    int64_t formId = 0;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0002");
    formDataProxies.push_back(formDataProxy);
    int32_t result = proxy->RequestPublishProxyForm(want, withFormBindingData, formProviderData,
                                                    formId, formDataProxies);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RequestPublishProxyForm_0200, end";
}

/*
 * @tc.name: RegisterPublishFormInterceptor_0100
 * @tc.desc: test RegisterPublishFormInterceptor function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t result = proxy->RegisterPublishFormInterceptor(nullptr);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0100, end";
}

/*
 * @tc.name: RegisterPublishFormInterceptor_0200
 * @tc.desc: test RegisterPublishFormInterceptor function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t result = proxy->RegisterPublishFormInterceptor(nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterPublishFormInterceptor_0200, end";
}

/*
 * @tc.name: UnregisterPublishFormInterceptor_0100
 * @tc.desc: test UnregisterPublishFormInterceptor function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t result = proxy->UnregisterPublishFormInterceptor(nullptr);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0100, end";
}

/*
 * @tc.name: UnregisterPublishFormInterceptor_0200
 * @tc.desc: test UnregisterPublishFormInterceptor function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    int32_t result = proxy->UnregisterPublishFormInterceptor(nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterPublishFormInterceptor_0200, end";
}

/*
 * @tc.name: RegisterClickEventObserver_0100
 * @tc.desc: test RegisterClickEventObserver function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RegisterClickEventObserver_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterClickEventObserver_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::string bundleName = "1";
    std::string formEventType = "1";

    int32_t result = proxy->RegisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterClickEventObserver_0100, end";
}

/*
 * @tc.name: RegisterClickEventObserver_0200
 * @tc.desc: test RegisterClickEventObserver function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RegisterClickEventObserver_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterClickEventObserver_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::string bundleName = "1";
    std::string formEventType = "1";

    int32_t result = proxy->RegisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(result, errCode);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RegisterClickEventObserver_0200, end";
}

/*
 * @tc.name: UnregisterClickEventObserver_0100
 * @tc.desc: test UnregisterClickEventObserver function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UnregisterClickEventObserver_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterClickEventObserver_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::string bundleName = "1";
    std::string formEventType = "1";

    int32_t result = proxy->UnregisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterClickEventObserver_0100, end";
}

/*
 * @tc.name: UnregisterClickEventObserver_0200
 * @tc.desc: test UnregisterClickEventObserver function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, UnregisterClickEventObserver_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterClickEventObserver_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = ERR_APPEXECFWK_FORM_SEND_FMS_MSG;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::string bundleName = "1";
    std::string formEventType = "1";

    int32_t result = proxy->UnregisterClickEventObserver(bundleName, formEventType, nullptr);
    EXPECT_EQ(result, errCode);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, UnregisterClickEventObserver_0200, end";
}

/*
 * @tc.name: SetFormsRecyclable_0100
 * @tc.desc: test SetFormsRecyclable function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetFormsRecyclable_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetFormsRecyclable_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    int32_t result = proxy->SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetFormsRecyclable_0100, end";
}

/*
 * @tc.name: SetFormsRecyclable_0200
 * @tc.desc: test SetFormsRecyclable function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, SetFormsRecyclable_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetFormsRecyclable_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    int32_t result = proxy->SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, SetFormsRecyclable_0200, end";
}

/*
 * @tc.name: RecycleForms_0100
 * @tc.desc: test RecycleForms function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecycleForms_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecycleForms_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    Want want;
    int32_t result = proxy->RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecycleForms_0100, end";
}

/*
 * @tc.name: RecycleForms_0200
 * @tc.desc: test RecycleForms function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecycleForms_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecycleForms_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    Want want;
    int32_t result = proxy->RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecycleForms_0200, end";
}

/*
 * @tc.name: RecoverForms_0100
 * @tc.desc: test RecoverForms function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecoverForms_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecoverForms_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    int32_t errCode = -1;
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(errCode)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    Want want;
    int32_t result = proxy->RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecoverForms_0100, end";
}

/*
 * @tc.name: RecoverForms_0200
 * @tc.desc: test RecoverForms function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecoverForms_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecoverForms_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);

    std::vector<int64_t> formIds{0};
    Want want;
    int32_t result = proxy->RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormMgrProxyTest, RecoverForms_0200, end";
}

/*
 * @tc.name: RecoverForms_0201
 * @tc.desc: test RecoverForms function and return ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RecoverForms_0201, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormWithSnapshot_0201, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = false;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RequestPublishFormWithSnapshotTest_0100
 * @tc.desc: test RequestPublishFormWithSnapshot function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = false;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}

/*
 * @tc.name: RequestPublishFormWithSnapshotTest_0200
 * @tc.desc: test RequestPublishFormWithSnapshot function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_OK, result);
}

/*
 * @tc.name: RequestPublishFormWithSnapshotTest_0300
 * @tc.desc: test RequestPublishFormWithSnapshot function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestPublishFormWithSnapshotTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    Want want;
    bool withFormBindingData = false;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    int32_t result = proxy->RequestPublishFormWithSnapshot(want, withFormBindingData, formBindingData, formId);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: RequestOverflowTest_0100
 * @tc.desc: test RequestOverflow function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestOverflowTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestOverflowTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    int32_t result = proxy->RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}
 
/*
 * @tc.name: RequestOverflowTest_0200
 * @tc.desc: test RequestOverflow function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestOverflowTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestOverflowTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    int32_t result = proxy->RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(ERR_OK, result);
}
 
/*
 * @tc.name: RequestOverflowTest_0300
 * @tc.desc: test RequestOverflow function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, RequestOverflowTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, RequestOverflowTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    int32_t result = proxy->RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}
 
/*
 * @tc.name: ChangeSceneAnimationStateTest_0100
 * @tc.desc: test ChangeSceneAnimationState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    int32_t state = 1;
    int32_t result = proxy->ChangeSceneAnimationState(formId, state);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}
 
/*
 * @tc.name: ChangeSceneAnimationStateTest_0200
 * @tc.desc: test ChangeSceneAnimationState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    int32_t state = 1;
    int32_t result = proxy->ChangeSceneAnimationState(formId, state);
    EXPECT_EQ(ERR_OK, result);
}
 
/*
 * @tc.name: ChangeSceneAnimationStateTest_0300
 * @tc.desc: test ChangeSceneAnimationState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, ChangeSceneAnimationStateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    int32_t state = 1;
    int32_t result = proxy->ChangeSceneAnimationState(formId, state);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}

/*
 * @tc.name: GetFormRectTest_0100
 * @tc.desc: test GetFormRect function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormRectTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormRectTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Rect rect;
    int32_t result = proxy->GetFormRect(formId, rect);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}
 
/*
 * @tc.name: GetFormRectTest_0200
 * @tc.desc: test GetFormRect function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormRectTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormRectTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _))
        .WillRepeatedly(DoAll(Invoke(std::bind(SendRequestReplace, _1, _2, _3, _4,
        ERR_OK, true)), Return(NO_ERROR)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Rect rect;
    int32_t result = proxy->GetFormRect(formId, rect);
    EXPECT_EQ(ERR_APPEXECFWK_PARCEL_ERROR, result);
}
 
/*
 * @tc.name: GetFormRectTest_0300
 * @tc.desc: test GetFormRect function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormMgrProxyTest, GetFormRectTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormMgrProxyTest, GetFormRectTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormMgrProxy> proxy = std::make_shared<FormMgrProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    int64_t formId = 1;
    Rect rect;
    int32_t result = proxy->GetFormRect(formId, rect);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_SEND_FMS_MSG, result);
}
}
