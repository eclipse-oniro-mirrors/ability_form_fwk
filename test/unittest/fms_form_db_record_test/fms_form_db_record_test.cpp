/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <string>
#include <thread>
#define private public
#include "form_db_cache.h"
#include "form_mgr_adapter.h"
#undef private
#include "form_record.h"
#include "fms_log_wrapper.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormDbRecordTest : public testing::Test {
public:
    void InitFormRecord();
    FormRecord formRecord_;
    FormMgrAdapter formMgrAdapter_;
};

void FmsFormDbRecordTest::InitFormRecord()
{
    formRecord_.isInited = false;
    formRecord_.needFreeInstall = false;
    formRecord_.versionUpgrade = false;
    formRecord_.needRefresh = false;
    formRecord_.packageName = "TestPackageName";
    formRecord_.bundleName = "TestBundleName";
    formRecord_.moduleName = "TestModuleName";
    formRecord_.abilityName = "TestAbilityName";
    formRecord_.formName = "TestFormName";
    formRecord_.specification = 0;
    formRecord_.isEnableUpdate = false;
    formRecord_.updateDuration = 0;
    formRecord_.updateAtHour = 0;
    formRecord_.updateAtMin = 0;
    formRecord_.hapSourceDirs.emplace_back("hapSourceDirs1");
    formRecord_.formName = "formNameTest";
    formRecord_.formTempFlag = false;
    formRecord_.formUserUids.emplace_back(1);
    formRecord_.formVisibleNotify = false;
    formRecord_.formVisibleNotifyState = 0;
}

/**
 * @tc.name: FmsFormDbRecordTest_001
 * @tc.desc: Verify functionName Start.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_001 start";
    FormDbCache::GetInstance().Start();
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_001 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_002
 * @tc.desc: Verify functionName UpdateDBRecord.
 * @tc.details: Verify that the return value is correct, when the input callIds is [1].
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_002 start";
    InitFormRecord();
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().UpdateDBRecord(0, formRecord_));
    FormDbCache::GetInstance().DeleteFormInfo(0);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_002 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_003
 * @tc.desc: Verify functionName UpdateDBRecord.
 * @tc.details: Verify that the return value is correct, when the input callIds is [0, 1].
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_003 start";
    InitFormRecord();
    formRecord_.formUserUids.emplace_back(0);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().UpdateDBRecord(1, formRecord_));
    FormDbCache::GetInstance().DeleteFormInfo(1);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_003 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_004
 * @tc.desc: Verify functionName UpdateDBRecord.
 * @tc.details: Verify that the return value is correct, when the input callIds is [1, 2].
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_004 start";
    InitFormRecord();
    formRecord_.formUserUids.emplace_back(2);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().UpdateDBRecord(1, formRecord_));
    FormDbCache::GetInstance().DeleteFormInfo(1);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_004 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_005
 * @tc.desc: Verify functionName UpdateDBRecord.
 * @tc.details: Verify that the return value is correct, when the input formId is 0.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_005 start";
    InitFormRecord();
    formRecord_.formUserUids.emplace_back(2);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().UpdateDBRecord(0, formRecord_));
    FormDbCache::GetInstance().DeleteFormInfo(0);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_005 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_006
 * @tc.desc: Verify functionName GetDBRecord.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 start";
    InitFormRecord();
    formRecord_.formUserUids.emplace_back(2);
    FormDbCache::GetInstance().UpdateDBRecord(1, formRecord_);
    FormDbCache::GetInstance().UpdateDBRecord(0, formRecord_);

    FormRecord record;
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetDBRecord(0, record));

    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 formName: " << record.formName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 bundleName:" << record.bundleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 moduleName:" << record.moduleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 abilityName:" << record.abilityName;
    for (unsigned int j = 0; j < record.formUserUids.size(); j++) {
        GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 formUserUids:" << record.formUserUids[j];
    }

    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 -------------------";

    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetDBRecord(1, record));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 formName: " << record.formName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 bundleName:" << record.bundleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 moduleName:" << record.moduleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 abilityName:" << record.abilityName;
    for (unsigned int j = 0; j < record.formUserUids.size(); j++) {
        GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 formUserUids:" << record.formUserUids[j];
    }
    FormDbCache::GetInstance().DeleteFormInfo(0);
    FormDbCache::GetInstance().DeleteFormInfo(1);

    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_006 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_007
 * @tc.desc: Verify functionName GetAllDBRecord.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 start";

    InitFormRecord();
    FormDbCache::GetInstance().UpdateDBRecord(0, formRecord_);
    formRecord_.formUserUids.emplace_back(0);
    FormDbCache::GetInstance().UpdateDBRecord(1, formRecord_);

    FormRecord record;
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetDBRecord(0, record));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 formName: " << record.formName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 bundleName:" << record.bundleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 moduleName:" << record.moduleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 abilityName:" << record.abilityName;
    for (unsigned int j = 0; j < record.formUserUids.size(); j++) {
        GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 formUserUids:" << record.formUserUids[j];
    }

    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 -------------------";

    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetDBRecord(1, record));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 formName: " << record.formName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 bundleName:" << record.bundleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 moduleName:" << record.moduleName;
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 abilityName:" << record.abilityName;
    for (unsigned int j = 0; j < record.formUserUids.size(); j++) {
        GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 formUserUids:" << record.formUserUids[j];
    }
    FormDbCache::GetInstance().DeleteFormInfo(0);
    FormDbCache::GetInstance().DeleteFormInfo(1);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_007 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_008
 * @tc.desc: Verify functionName UpdateDBRecord.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_008 start";
    InitFormRecord();
    FormDbCache::GetInstance().UpdateDBRecord(2, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteFormInfo(2));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_008 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_009
 * @tc.desc: Verify functionName DeleteFormInfoByBundleName.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_009 start";
    InitFormRecord();
    int64_t formId = 2;
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, FormDbCache::GetInstance().GetDBRecord(formId, formDbInfo));

    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfoNolock(formDbInfo));
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfoNolock(formDbInfo));

    formRecord_.moduleName = "TestModuleName2";
    FormDBInfo formDbInfo2(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfoNolock(formDbInfo2));

    std::vector<FormDBInfo> removedDBForms;
    int32_t userId = 102;
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteFormInfoByBundleName(formRecord_.bundleName,
                                                                           userId, removedDBForms));
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteFormInfoByBundleName(formRecord_.bundleName,
                                                                            formRecord_.providerUserId,
                                                                            removedDBForms));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_009 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_0010
 * @tc.desc: Verify functionName GetNoHostDBForms.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_010 start";
    InitFormRecord();
    int64_t formId = 2;
    formRecord_.formUserUids.emplace_back(2);
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));

    const int uid1 = 1;
    const int uid2 = 2;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDBList;
    std::map<int64_t, bool> foundFormsMap;
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetNoHostDBForms(uid2, noHostFormDBList, foundFormsMap));
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetNoHostDBForms(uid1, noHostFormDBList, foundFormsMap));
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().GetNoHostDBForms(uid1, noHostFormDBList, foundFormsMap));

    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteFormInfo(formId));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_010 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_0011
 * @tc.desc: Verify functionName GetMatchCount.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_011 start";
    InitFormRecord();
    int64_t formId = 2;
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));

    int retNum = 1;
    EXPECT_EQ(retNum, FormDbCache::GetInstance().GetMatchCount(formRecord_.bundleName, formRecord_.moduleName));
    FormDbCache::GetInstance().DeleteDBFormsByUserId(formRecord_.providerUserId);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_011 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_0012
 * @tc.desc: Verify functionName GetNoHostInvalidDBForms.
 * @tc.details: Verify that the return value is correct, and the noHostFormDBList is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_012 start";
    InitFormRecord();
    int64_t formId = 2;
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));

    int32_t userId1 = 102;
    int32_t userId2 = formRecord_.providerUserId;
    int32_t callingUid1 = 102;
    int32_t callingUid2 = 1;
    std::set<int64_t> matchedFormIds;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDBList;
    std::map<int64_t, bool> foundFormsMap;
    FormDbCache::GetInstance().GetNoHostInvalidDBForms(userId1, callingUid2, matchedFormIds,
                                                       noHostFormDBList, foundFormsMap);
    EXPECT_EQ(noHostFormDBList.size(), 0);

    FormDbCache::GetInstance().GetNoHostInvalidDBForms(userId2, callingUid1, matchedFormIds,
                                                       noHostFormDBList, foundFormsMap);
    EXPECT_EQ(noHostFormDBList.size(), 0);

    FormDbCache::GetInstance().GetNoHostInvalidDBForms(userId2, callingUid2, matchedFormIds,
                                                       noHostFormDBList, foundFormsMap);
    EXPECT_EQ(noHostFormDBList.size(), 1);

    FormDbCache::GetInstance().GetNoHostInvalidDBForms(userId2, callingUid2, matchedFormIds,
                                                       noHostFormDBList, foundFormsMap);
    EXPECT_EQ(noHostFormDBList.size(), 1);

    formRecord_.formUserUids.emplace_back(2);
    FormDBInfo formDbInfo2(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo2));
    FormDbCache::GetInstance().GetNoHostInvalidDBForms(userId2, callingUid2, matchedFormIds,
                                                       noHostFormDBList, foundFormsMap);
    EXPECT_EQ(foundFormsMap.size(), 1);

    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_012 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_013
 * @tc.desc: Verify functionName DeleteInvalidDBForms.
 * @tc.details: Verify that the return value is correct, and the removeFormsMap is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_013 start";
    InitFormRecord();
    int64_t formId = 2;
    formRecord_.formUserUids.emplace_back(2);
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));

    int32_t userId = formRecord_.providerUserId;
    int32_t callingUid = 1;
    std::set<int64_t> matchedFormIds;
    std::map<int64_t, bool> removeFormsMap;
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteInvalidDBForms(userId, callingUid, matchedFormIds,
                                                                      removeFormsMap));
    EXPECT_EQ(removeFormsMap.size(), 1);
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_013 end";
}

/**
 * @tc.name: FmsFormDbRecordTest_014
 * @tc.desc: Verify functionName IsHostOwner.
 * @tc.details: Verify that the return value is correct.
 */
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_014 start";
    int64_t formId = 2;
    int32_t userId1 = 1;
    int32_t userId2 = 102;
    EXPECT_EQ(false, FormDbCache::GetInstance().IsHostOwner(formId, userId1));

    InitFormRecord();
    FormDBInfo formDbInfo(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().SaveFormInfo(formDbInfo));
    EXPECT_EQ(true, FormDbCache::GetInstance().IsHostOwner(formId, userId1));
    EXPECT_EQ(false, FormDbCache::GetInstance().IsHostOwner(formId, userId2));

    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().DeleteFormInfo(formId));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_014 end";
}

/**
 * @tc.number: FmsFormDbRecordTest_015
 * @tc.name: UpdateFormLocation
 * @tc.desc: Verify that the vector can be operated normally.
 * @tc.details: Determine whether an element exists in the vector.
*/
HWTEST_F(FmsFormDbRecordTest, FmsFormDbRecordTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_015 start";
    InitFormRecord();
    int64_t formId = 0;
    int32_t formLocation = 1;
    FormDbCache::GetInstance().UpdateDBRecord(formId, formRecord_);
    EXPECT_EQ(ERR_OK, FormDbCache::GetInstance().UpdateFormLocation(formId, formLocation));
    FormDbCache::GetInstance().DeleteFormInfo(formId);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_FORM_ID, FormDbCache::GetInstance().UpdateFormLocation(formId, formLocation));
    GTEST_LOG_(INFO) << "FmsFormDbRecordTest_015 end";
}
}
