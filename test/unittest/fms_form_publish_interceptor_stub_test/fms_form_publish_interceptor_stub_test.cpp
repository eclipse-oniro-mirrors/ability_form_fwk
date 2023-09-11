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

#include <gtest/gtest.h>
#include <map>
#include <string>
#include <thread>

#include "appexecfwk_errors.h"
#include "data_proxy_observer_stub.h"
#include "datashare_log.h"
#include "datashare_helper.h"
#define private public
#include "form_publish_interceptor_stub.h"
#include "form_item_info.h"
#undef private
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_record.h"
#include "form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"


using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormPublishInterceptorStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormPublishInterceptorStubTest::SetUpTestCase()
{}

void FormPublishInterceptorStubTest::TearDownTestCase()
{}

void FormPublishInterceptorStubTest::SetUp()
{}

void FormPublishInterceptorStubTest::TearDown()
{}

/**
 * @tc.number: FormPublishInterceptorStubTest_001
 * @tc.name: SubscribeFormData
 * @tc.desc: Verify that the return value is correct.
 * @tc.details:
 *      temporaryFlag is true, and tempForms is empty, then create a tempForm.
 *      formRecords_ is empty, then create formRecords.
 */
HWTEST_F(FormPublishInterceptorStubTest, FormPublishInterceptorStubTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormPublishInterceptorStubTest_001 start";
    FormPublishInterceptorStub formPublishInterceptorStub;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = formPublishInterceptorStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormPublishInterceptorStubTest_001 end";
}
}