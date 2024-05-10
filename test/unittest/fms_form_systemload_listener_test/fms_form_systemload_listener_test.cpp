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
#include <gtest/gtest.h>
#include "form_systemload_listener.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormSystemloadListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static void OnSystemloadLevel(int32_t level);

protected:
};

void FmsFormSystemloadListenerTest::SetUpTestCase() {}
void FmsFormSystemloadListenerTest::TearDownTestCase() {}
void FmsFormSystemloadListenerTest::SetUp() {}
void FmsFormSystemloadListenerTest::TearDown() {}
void FmsFormSystemloadListenerTest::OnSystemloadLevel(int32_t level)
{
    GTEST_LOG_(INFO) << "OnSystemloadLevel call back";
}

/**
 * @tc.number: SetOnSystemloadLevel_0001
 * @tc.name: OnSystemloadLevel.
 * @tc.desc: Verify that the OnSystemloadLevel interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormSystemloadListenerTest, SetOnSystemloadLevel_0001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "SetOnSystemloadLevel_0001 start";
    FormSystemloadListener formSystemloadListener(nullptr);
    formSystemloadListener.OnSystemloadLevel(0);
    GTEST_LOG_(INFO) << "SetOnSystemloadLevel_0001 end";
}

/**
 * @tc.number: SetOnSystemloadLevel_0002
 * @tc.name: OnSystemloadLevel.
 * @tc.desc: Verify that the OnSystemloadLevel interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormSystemloadListenerTest, SetOnSystemloadLevel_0002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "SetOnSystemloadLevel_0002 start";
    OnSystemloadLevel(2);
    FormSystemloadListener formSystemloadListener(OnSystemloadLevel);
    formSystemloadListener.OnSystemloadLevel(0);
    GTEST_LOG_(INFO) << "SetOnSystemloadLevel_0002 end";
}

}