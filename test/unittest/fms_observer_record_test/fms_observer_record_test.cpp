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

#include "form_observer_record.h"
#include "form_constants.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FmsFormObserverRecordTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FmsFormObserverRecordTest::SetUpTestCase() {}

void FmsFormObserverRecordTest::TearDownTestCase() {}

void FmsFormObserverRecordTest::SetUp() {}

void FmsFormObserverRecordTest::TearDown() {}

/**
 * @tc.number: FmsFormObserverRecordTest_001
 * @tc.name: SetDeathRecipient.
 * @tc.desc: Verify that the SetDeathRecipient interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_001 start";
    FormObserverRecord formObserverRecord;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formObserverRecord.SetDeathRecipient(callerToken, nullptr);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_001 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_002
 * @tc.name: SetFormAddObserver.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_002 start";
    FormObserverRecord formObserverRecord;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "bundle";
    EXPECT_EQ(ERR_OK, formObserverRecord.SetFormAddObserver(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_002 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_003
 * @tc.name: SetFormRemoveObserver.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_003, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_003 start";
    FormObserverRecord formObserverRecord;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    std::string bundleName = "bundle";
    EXPECT_EQ(ERR_OK, formObserverRecord.SetFormRemoveObserver(bundleName, callerToken));
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_003 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_004
 * @tc.name: onFormAdd.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_004, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_004 start";
    FormObserverRecord formObserverRecord;
    RunningFormInfo runningFormInfo;
    std::string bundleName = "bundle";
    formObserverRecord.onFormAdd(bundleName, runningFormInfo);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_004 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_005
 * @tc.name: onFormRemove.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_005, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_005 start";
    FormObserverRecord formObserverRecord;
    RunningFormInfo runningFormInfo;
    std::string bundleName = "bundle";
    formObserverRecord.onFormRemove(bundleName, runningFormInfo);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_005 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_006
 * @tc.name: CleanResource.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_006, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_006 start";
    FormObserverRecord formObserverRecord;
    RunningFormInfo runningFormInfo;
    wptr<IRemoteObject> remote;
    formObserverRecord.CleanResource(remote);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_006 end";
}
}
}
