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
#include <chrono>
#include <gtest/gtest.h>

#include "common_event.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "form_constants.h"
#define private public
#include "form_refresh_limiter.h"
#include "free_install_status_callback_proxy.h"
#include "free_install_status_callback_stub.h"
#undef private
#include "remote_native_token.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFreeInstallStatusCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFreeInstallStatusCallbackProxyTest::SetUpTestCase()
{
    RemoteNativeToken::SetNativeToken();
}
void FmsFreeInstallStatusCallbackProxyTest::TearDownTestCase() {}
void FmsFreeInstallStatusCallbackProxyTest::SetUp() {}
void FmsFreeInstallStatusCallbackProxyTest::TearDown() {}

class MolFreeInstallStatusCallBackStub : public FreeInstallStatusCallBackStub {
public:
    MolFreeInstallStatusCallBackStub() {};
    virtual ~MolFreeInstallStatusCallBackStub() = default;
    void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId) override {};

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        reply.WriteInt32(NO_ERROR);
        return returnCode_;
    }

    int32_t returnCode_ = NO_ERROR;
};

/**
 * @tc.number: Fms_FreeInstallStatusCallbackProxy_0001
 * @tc.name: OnInstallFinished.
 * @tc.desc: Verify that the OnInstallFinished interface executes normally and exits without exception.
 */
HWTEST_F(FmsFreeInstallStatusCallbackProxyTest,
    Fms_FreeInstallStatusCallbackProxy_0001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FreeInstallStatusCallbackProxy_0001 start";
    sptr<MolFreeInstallStatusCallBackStub> impl = new (std::nothrow) MolFreeInstallStatusCallBackStub();
    auto freeInstallStatusCallBackProxy = std::make_shared<FreeInstallStatusCallBackProxy>(impl);
    int32_t resultCode = 0;
    const Want want;
    int32_t userId = 0;
    impl->returnCode_ = TRANSACTION_ERR;
    freeInstallStatusCallBackProxy->OnInstallFinished(resultCode, want, userId);
    impl->returnCode_ = NO_ERROR;
    GTEST_LOG_(INFO) << "Fms_FreeInstallStatusCallbackProxy_0001 end";
}

/**
 * @tc.number: Fms_FreeInstallStatusCallbackProxy_0002
 * @tc.name: OnInstallFinished.
 * @tc.desc: Verify that the OnInstallFinished interface executes normally and exits without exception.
 */
HWTEST_F(FmsFreeInstallStatusCallbackProxyTest,
    Fms_FreeInstallStatusCallbackProxy_0002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "Fms_FreeInstallStatusCallbackProxy_0002 start";
    sptr<MolFreeInstallStatusCallBackStub> impl = new (std::nothrow) MolFreeInstallStatusCallBackStub();
    auto freeInstallStatusCallBackProxy = std::make_shared<FreeInstallStatusCallBackProxy>(impl);
    int32_t resultCode = 0;
    const Want want;
    int32_t userId = 0;
    freeInstallStatusCallBackProxy->OnInstallFinished(resultCode, want, userId);
    GTEST_LOG_(INFO) << "Fms_FreeInstallStatusCallbackProxy_0002 end";
}
}
