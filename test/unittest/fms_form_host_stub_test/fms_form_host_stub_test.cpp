/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_host_stub.h"
#include "form_mgr_errors.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "mock_form_host_client.h"
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormHostStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormHostStubTest::SetUpTestCase()
{}

void FormHostStubTest::TearDownTestCase()
{}

void FormHostStubTest::SetUp()
{}

void FormHostStubTest::TearDown()
{}

/**
 * @tc.name: FormHostStubTest_001
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_001, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_002
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_002, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_003
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_003, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_004
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_004, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 4;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}
}  // namespace AppExecFwk
}  // namespace OHOS
