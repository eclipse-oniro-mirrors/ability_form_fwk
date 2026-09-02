/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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
#include "form_host_proxy.h"
#undef private
#undef protected
#include "form_constants.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockWriteInterfaceToken(bool mockRet);

namespace {
class FmsFormHostProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormHostProxyTest::SetUpTestCase() {}
void FmsFormHostProxyTest::TearDownTestCase() {}
void FmsFormHostProxyTest::SetUp()
{
    MockWriteInterfaceToken(true);
}
void FmsFormHostProxyTest::TearDown() {}
}
