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
#include <gtest/gtest.h>
#include <memory>

#include "appexecfwk_errors.h"
#include "gmock/gmock.h"
#include "form_mgr_errors.h"
#include "form_publish_interceptor_proxy.h"
#include "mock_form_token.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormPublishInterceptorProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockIRemoteObject_ = new MockIRemoteObject();
        formRenderProxy_ = new FormPublishInterceptorProxy(mockIRemoteObject_);
    }
    sptr<MockIRemoteObject> mockIRemoteObject_;
    sptr<FormPublishInterceptorProxy> formRenderProxy_;
};

/**
 * @tc.name: FormPublishInterceptorProxyTest_0001
 * @tc.desc: test ProcessPublishForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FormPublishInterceptorProxyTest, FormPublishInterceptorProxyTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormPublishInterceptorProxyTest_0001 starts";
    EXPECT_CALL(*mockIRemoteObject_, SendRequest(_, _, _, _)).Times(1)
        .WillOnce(Return(ERR_OK));
    Want want = {};
    int result = formRenderProxy_->ProcessPublishForm(want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormPublishInterceptorProxyTest_0001 test ends";
}
}