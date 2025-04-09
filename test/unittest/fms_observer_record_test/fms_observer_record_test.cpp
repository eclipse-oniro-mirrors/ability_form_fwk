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

#define private public
#include "form_observer/form_observer_record.h"
#include "form_constants.h"
#include "mock_form_provider_client.h"
#include "form_mgr_errors.h"

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

/**
 * @tc.number: FmsFormObserverRecordTest_007
 * @tc.name: SetFormEventObserver.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_007, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_007 start";
    FormObserverRecord formObserverRecord;
    std::string bundleName = "bundleName";
    std::string formEventType = "";
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formObserverRecord.SetFormEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    ret = formObserverRecord.SetFormEventObserver(bundleName, formEventType, callerToken2);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formEventType = "test";
    ret = formObserverRecord.SetFormEventObserver(bundleName, formEventType, callerToken2);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_007 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_008
 * @tc.name: RemoveFormEventObserver.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_008, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_008 start";
    FormObserverRecord formObserverRecord;
    std::string bundleName = "bundleName";
    std::string formEventType = "";
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formObserverRecord.RemoveFormEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formEventType = "test";
    ret = formObserverRecord.RemoveFormEventObserver(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    ret = formObserverRecord.RemoveFormEventObserver(bundleName, formEventType, callerToken2);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formEventType = "message";
    ret = formObserverRecord.RemoveFormEventObserver(bundleName, formEventType, callerToken2);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_008 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_009
 * @tc.name: RemoveFormEventObserverLocked.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_009, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_009 start";
    FormObserverRecord formObserverRecord;
    std::string bundleName = "bundleName";
    FormEventId formEventType = FormEventId::FORM_EVENT_CALL;
    sptr<IRemoteObject> callerToken = nullptr;
    auto ret = formObserverRecord.RemoveFormEventObserverLocked(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    formObserverRecord.formEventObservers_.clear();
    FormObserverRecordInner recordInner(callerToken);
    recordInner.PushEvent(formEventType);
    recordInner.SetBindHostBundle(bundleName);
    std::vector<FormObserverRecordInner> observerVec{recordInner};
    formObserverRecord.formEventObservers_[bundleName] = observerVec;
    ret = formObserverRecord.RemoveFormEventObserverLocked(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_OK);

    formObserverRecord.formEventObservers_.clear();
    sptr<IRemoteObject> callerToken2 = new (std::nothrow) MockFormProviderClient();
    FormObserverRecordInner recordInner2(callerToken2);
    std::vector<FormObserverRecordInner> observerVec2{recordInner};
    ret = formObserverRecord.RemoveFormEventObserverLocked(bundleName, formEventType, callerToken);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_009 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_010
 * @tc.name: ClearDeathRemoteObserver.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_010, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_010 start";
    FormObserverRecord formObserverRecord;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    FormObserverRecordInner recordInner(callerToken);
    std::vector<FormObserverRecordInner> observerVec{recordInner};
    formObserverRecord.formEventObservers_[bundleName] = observerVec;
    wptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    EXPECT_NE(remote.promote(), nullptr);
    formObserverRecord.ClearDeathRemoteObserver(remote);
    EXPECT_EQ(remote.promote(), nullptr);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_010 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_011
 * @tc.name: RemoveFormEventObserverLocked.
 * @tc.desc: Verify that the SetFormAddObserver interface executes normally and exits without exception.
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_011, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_011 start";
    sptr<IRemoteObject> callerToken = nullptr;
    FormObserverRecordInner formObserverRecordInner(callerToken);
    FormEventId type = FormEventId::FORM_EVENT_NON;
    formObserverRecordInner.eventGroup_.push_back(FormEventId::FORM_EVENT_FORM_REMOVE);
    formObserverRecordInner.eventGroup_.push_back(FormEventId::FORM_EVENT_CALL);
    formObserverRecordInner.eventGroup_.push_back(FormEventId::FORM_EVENT_MESSAGE);
    auto size = formObserverRecordInner.eventGroup_.size();
    formObserverRecordInner.RemoveEvent(type);
    EXPECT_EQ(formObserverRecordInner.eventGroup_.size(), size);
    type = FormEventId::FORM_EVENT_FORM_REMOVE;
    formObserverRecordInner.RemoveEvent(type);
    EXPECT_EQ(formObserverRecordInner.eventGroup_.size(), size - 1);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_011 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_012
 * @tc.name: OnRemoteDied.
 * @tc.desc: OnRemoteDied
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_012, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_012 start";
    FormObserverRecord::ClientDeathRecipient clientDeathRecipient;
    wptr<IRemoteObject> remote;
    clientDeathRecipient.OnRemoteDied(remote);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_012 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_013
 * @tc.name: NotifyFormEvent.
 * @tc.desc: NotifyFormEvent
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_013, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_013 start";
    FormObserverRecord formObserverRecord;
    sptr<IRemoteObject> callerToken = nullptr;
    FormObserverRecordInner recordInner(callerToken);
    RunningFormInfo runningFormInfo;
    std::string formEventType = "";
    formObserverRecord.NotifyFormEvent(recordInner, FormEventId::FORM_EVENT_NON, runningFormInfo, formEventType);
    formObserverRecord.NotifyFormEvent(recordInner, FormEventId::FORM_EVENT_CALL, runningFormInfo, formEventType);
    formObserverRecord.NotifyFormEvent(recordInner, FormEventId::FORM_EVENT_MESSAGE, runningFormInfo, formEventType);
    formObserverRecord.NotifyFormEvent(recordInner, FormEventId::FORM_EVENT_ROUTER, runningFormInfo, formEventType);
    formObserverRecord.NotifyFormEvent(recordInner, FormEventId::FORM_EVENT_FORM_ADD, runningFormInfo, formEventType);
    formObserverRecord.NotifyFormEvent(recordInner,
        FormEventId::FORM_EVENT_FORM_REMOVE, runningFormInfo, formEventType);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_013 end";
}

/**
 * @tc.number: FmsFormObserverRecordTest_014
 * @tc.name: SetFormEventObserverLocked.
 * @tc.desc: SetFormEventObserverLocked
 */
HWTEST_F(FmsFormObserverRecordTest, FmsFormObserverRecordTest_014, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_014 start";
    FormObserverRecord formObserverRecord;
    std::string bundleName = "";
    sptr<IRemoteObject> callerToken;
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_NON, callerToken);
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_CALL, callerToken);
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_MESSAGE, callerToken);
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_ROUTER, callerToken);
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_FORM_ADD, callerToken);
    formObserverRecord.SetFormEventObserverLocked(bundleName, FormEventId::FORM_EVENT_FORM_REMOVE, callerToken);
    GTEST_LOG_(INFO) << "FmsFormObserverRecordTest_014 end";
}
}
}
