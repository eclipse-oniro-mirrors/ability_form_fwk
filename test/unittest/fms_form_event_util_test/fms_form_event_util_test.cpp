/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "common/event/form_event_util.h"
#include "common/timer_mgr/form_timer_mgr.h"
#undef private
#include "fms_log_wrapper.h"
#include "ipc_types.h"
#include "mock_bundle_mgr.h"
#include "mock_form_provider_client.h"
#define private public
#include "form_render/form_render_mgr.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using ::testing::_;
using ::testing::Invoke;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgReferee;

static const std::string FORM_HOST_BUNDLE_NAME = "com.form.provider.service";
static const std::string PARAM_PROVIDER_MODULE_NAME = "com.form.provider.app.test.ability";
static const std::string FORM_PROVIDER_ABILITY_NAME = "com.form.provider.app.test.ability";
static const std::string FORM_NAME = "formName";

extern void MockGetFormsInfoByBundle(bool mockRet);
extern void MockGetFormRecord(bool mockRet);
extern void MockGetBundlePackInfo(bool mockRet);
extern void MockSetFormTempFlag(bool mockRet);
extern void MockGetMatchCount(bool mockRet);
extern void MockGetReCreateFormRecordsByBundleName(bool mockRet);
extern void MockGetUpdatedForm(bool mockRet);
extern void MockGetPackageForm(bool mockRet);
extern void MockGetNoHostDBFormsOne(bool mockRet);
extern void MockGetNoHostDBFormsTwo(bool mockRet);
extern void MockGetNoHostTempFormsOne(bool mockRet);
extern void MockGetNoHostTempFormsTwo(bool mockRet);
extern void MockNotifyProviderFormsBatchDelete(bool mockRet);

namespace {
class FmsFormEventUtilTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FmsFormEventUtilTest::SetUp()
{}

void FmsFormEventUtilTest::TearDown()
{}

/**
 * @tc.name: FormEventUtil_007
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_007 start";
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    BundleInfo bundleInfo;
    EXPECT_EQ(false, FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo));
    GTEST_LOG_(INFO) << "FormEventUtil_007 end";
}

/**
 * @tc.name: FormEventUtil_008
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_008 start";
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    targetForms.emplace_back(formInfo);
    BundleInfo bundleInfo;
    MockGetUpdatedForm(false);
    EXPECT_EQ(false, FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo));
    GTEST_LOG_(INFO) << "FormEventUtil_008 end";
}

/**
 * @tc.name: FormEventUtil_009
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_009 start";
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    targetForms.emplace_back(formInfo);
    BundleInfo bundleInfo;
    MockGetUpdatedForm(true);
    EXPECT_EQ(true, FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo));
    GTEST_LOG_(INFO) << "FormEventUtil_009 end";
}

/**
 * @tc.name: FormEventUtil_010
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_010 start";
    int64_t formId = 1;
    FormRecord formRecord;
    BundlePackInfo bundlePackInfo;
    BundleInfo bundleInfo;
    MockGetPackageForm(false);
    EXPECT_EQ(false, FormEventUtil::ProviderFormUpdated(formId, formRecord, bundlePackInfo, bundleInfo));
    GTEST_LOG_(INFO) << "FormEventUtil_010 end";
}

/**
 * @tc.name: FormEventUtil_011
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_011 start";
    int64_t formId = 1;
    FormRecord formRecord;
    BundlePackInfo bundlePackInfo;
    BundleInfo bundleInfo;
    MockGetPackageForm(true);
    EXPECT_EQ(true, FormEventUtil::ProviderFormUpdated(formId, formRecord, bundlePackInfo, bundleInfo));
    GTEST_LOG_(INFO) << "FormEventUtil_011 end";
}

/**
 * @tc.name: FormEventUtil_024
 * @tc.desc: test HandleBundleFormInfoChanged function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_024 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    bool needReload = false;
    FormEventUtil::HandleBundleFormInfoChanged(bundleName, userId, needReload);
    EXPECT_EQ(true, needReload);
    GTEST_LOG_(INFO) << "FormEventUtil_024 end";
}

/**
 * @tc.name: FormEventUtil_056
 * @tc.desc: test HandleAdditionalInfoChanged function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_056, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_056 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    MockGetFormRecord(false);
    EXPECT_EQ(false, FormEventUtil::HandleAdditionalInfoChanged(bundleName));

    MockGetFormRecord(true);
    MockSetFormTempFlag(true);
    EXPECT_EQ(true, FormEventUtil::HandleAdditionalInfoChanged(bundleName));
    GTEST_LOG_(INFO) << "FormEventUtil_056 end";
}

/**
 * @tc.name: FormEventUtil_057
 * @tc.desc: test HandleAdditionalInfoChanged function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_057, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_057 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int64_t formId = 1;
    int64_t updateDuration = 2 * Constants::TIME_CONVERSION;
    MockGetFormRecord(true);
    MockSetFormTempFlag(false);
    FormTimerMgr::GetInstance().AddFormTimer(formId, updateDuration, 0);

    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.apiTargetVersion = 11;
    EXPECT_CALL(*bmsProxy, GetApplicationInfoV9(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    std::string additionalInfo = "formUpdateLevel:10";
    EXPECT_CALL(*bmsProxy, GetAdditionalInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(additionalInfo), Return(ERR_OK)));

    EXPECT_EQ(true, FormEventUtil::HandleAdditionalInfoChanged(bundleName));

    FormTimer formTimer;
    FormTimerMgr::GetInstance().GetIntervalTimer(formId, formTimer);

    EXPECT_EQ(formTimer.period, 10 * Constants::TIME_CONVERSION);
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormEventUtil_057 end";
}

/**
 * @tc.name: FormEventUtil_059
 * @tc.desc: test ProviderFormUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_059 start";
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isDistributedForm = true;

    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    targetForms.emplace_back(formInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 1;
    MockGetUpdatedForm(false);
    EXPECT_EQ(false, FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo));
    EXPECT_EQ(1, formRecord.versionCode);
    GTEST_LOG_(INFO) << "FormEventUtil_059 end";
}

/**
 * @tc.name: FormEventUtil_061
 * @tc.desc: test ProviderFormUpdated IsDeleteCacheInUpgradeScene true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_061, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_061 start";
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.versionCode = 1;
    formRecord.formName = "testForm";
    formRecord.bundleName = FORM_HOST_BUNDLE_NAME;
    formRecord.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formRecord.providerUserId = 0;

    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = "testForm";
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 1;
    targetForms.emplace_back(formInfo);
    BundleInfo bundleInfo;
    bundleInfo.versionCode = 2;
    bundleInfo.name = FORM_HOST_BUNDLE_NAME;
    MockGetUpdatedForm(true);
    EXPECT_EQ(true, FormEventUtil::ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo));
    EXPECT_EQ(formRecord.versionCode, 2);
    EXPECT_EQ(formRecord.formId, formId);
    GTEST_LOG_(INFO) << "FormEventUtil_061 end";
}

/**
 * @tc.name: FormEventUtil_062
 * @tc.desc: test SetTimerCfgByMultUpdate empty config
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_062, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_062 start";
    const std::string configMultUpdateAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_062 end";
}

/**
 * @tc.name: FormEventUtil_063
 * @tc.desc: test SetTimerCfgByMultUpdate invalid size
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_063, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_063 start";
    const std::string configMultUpdateAt = "00:00,01:00,02:00,03:00,04:00,05:00,06:00,07:00,08:00,09:00,"
        "10:00,11:00,12:00,13:00,14:00,15:00,16:00,17:00,18:00,19:00,20:00,21:00,22:00,23:00,24:00";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_063 end";
}

/**
 * @tc.name: FormEventUtil_064
 * @tc.desc: test SetTimerCfgByMultUpdate invalid time format
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_064, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_064 start";
    const std::string configMultUpdateAt = "10:00:00";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_064 end";
}

/**
 * @tc.name: FormEventUtil_065
 * @tc.desc: test SetTimerCfgByMultUpdate invalid hour
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_065, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_065 start";
    const std::string configMultUpdateAt = "25:00";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_065 end";
}

/**
 * @tc.name: FormEventUtil_066
 * @tc.desc: test SetTimerCfgByMultUpdate invalid minute
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_066, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_066 start";
    const std::string configMultUpdateAt = "10:61";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_066 end";
}

/**
 * @tc.name: FormEventUtil_067
 * @tc.desc: test SetTimerCfgByMultUpdate valid config
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_067 start";
    const std::string configMultUpdateAt = "10:00,14:30";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate(configMultUpdateAt, cfg);
    EXPECT_TRUE(cfg.enableUpdate);
    EXPECT_EQ(2, (int)cfg.updateAtTimes.size());
    EXPECT_EQ(10, cfg.updateAtTimes[0][0]);
    EXPECT_EQ(0, cfg.updateAtTimes[0][1]);
    EXPECT_EQ(14, cfg.updateAtTimes[1][0]);
    EXPECT_EQ(30, cfg.updateAtTimes[1][1]);
    GTEST_LOG_(INFO) << "FormEventUtil_067 end";
}

/**
 * @tc.name: FormEventUtil_068
 * @tc.desc: test GetUpdateType interval no change
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_068, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_068 start";
    FormRecord record = {};
    record.updateDuration = 1000;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 1000;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_NO_CHANGE, type);
    GTEST_LOG_(INFO) << "FormEventUtil_068 end";
}

/**
 * @tc.name: FormEventUtil_069
 * @tc.desc: test GetUpdateType interval change
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_069, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_069 start";
    FormRecord record = {};
    record.updateDuration = 1000;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 2000;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_INTERVAL_CHANGE, type);
    GTEST_LOG_(INFO) << "FormEventUtil_069 end";
}

/**
 * @tc.name: FormEventUtil_070
 * @tc.desc: test GetUpdateType interval to atTime
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_070, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_070 start";
    FormRecord record = {};
    record.updateDuration = 1000;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 0;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_INTERVAL_TO_ATTIME, type);
    GTEST_LOG_(INFO) << "FormEventUtil_070 end";
}

/**
 * @tc.name: FormEventUtil_071
 * @tc.desc: test GetUpdateType atTime to interval
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_071, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_071 start";
    FormRecord record = {};
    record.updateDuration = 0;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 1000;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_ATTIME_TO_INTERVAL, type);
    GTEST_LOG_(INFO) << "FormEventUtil_071 end";
}

/**
 * @tc.name: FormEventUtil_072
 * @tc.desc: test GetUpdateType atTime no change
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_072, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_072 start";
    FormRecord record = {};
    record.updateDuration = 0;
    record.updateAtHour = 10;
    record.updateAtMin = 0;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 0;
    timerCfg.updateAtHour = 10;
    timerCfg.updateAtMin = 0;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_NO_CHANGE, type);
    GTEST_LOG_(INFO) << "FormEventUtil_072 end";
}

/**
 * @tc.name: FormEventUtil_073
 * @tc.desc: test GetUpdateType atTime change
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_073, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_073 start";
    FormRecord record = {};
    record.updateDuration = 0;
    record.updateAtHour = 10;
    record.updateAtMin = 0;
    FormTimerCfg timerCfg = {};
    timerCfg.updateDuration = 0;
    timerCfg.updateAtHour = 14;
    timerCfg.updateAtMin = 30;
    UpdateType type = FormEventUtil::GetUpdateType(record, timerCfg);
    EXPECT_EQ(TYPE_ATTIME_CHANGE, type);
    GTEST_LOG_(INFO) << "FormEventUtil_073 end";
}

/**
 * @tc.name: FormEventUtil_075
 * @tc.desc: Test HandleOnUnlock delegates to FormRenderMgr, inner state remains valid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_075, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_075 start";
    int32_t userId = 100;
    FormRenderMgr::GetInstance().InitRenderInner(false, userId);
    std::shared_ptr<FormRenderMgrInner> renderInner;
    EXPECT_TRUE(FormRenderMgr::GetInstance().GetFormRenderMgrInner(userId, renderInner));
    FormEventUtil::HandleOnUnlock(userId);
    EXPECT_TRUE(FormRenderMgr::GetInstance().GetFormRenderMgrInner(userId, renderInner));
    FormRenderMgr::GetInstance().DeleteRenderInner(userId);
    GTEST_LOG_(INFO) << "FormEventUtil_075 end";
}

/**
 * @tc.name: FormEventUtil_076
 * @tc.desc: Test SetTimerCfgByMultUpdate with valid time config.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_076, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_076 start";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate("10:30,14:00", cfg);
    EXPECT_TRUE(cfg.enableUpdate);
    EXPECT_EQ(cfg.updateAtTimes.size(), 2u);
    EXPECT_EQ(cfg.updateAtTimes[0][0], 10);
    EXPECT_EQ(cfg.updateAtTimes[0][1], 30);
    EXPECT_EQ(cfg.updateAtTimes[1][0], 14);
    EXPECT_EQ(cfg.updateAtTimes[1][1], 0);
    GTEST_LOG_(INFO) << "FormEventUtil_076 end";
}

/**
 * @tc.name: FormEventUtil_077
 * @tc.desc: Test SetTimerCfgByMultUpdate with invalid hour, invalid entry skipped.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_077, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_077 start";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate("25:00,10:30", cfg);
    EXPECT_TRUE(cfg.enableUpdate);
    EXPECT_EQ(cfg.updateAtTimes.size(), 1u);
    EXPECT_EQ(cfg.updateAtTimes[0][0], 10);
    EXPECT_EQ(cfg.updateAtTimes[0][1], 30);
    GTEST_LOG_(INFO) << "FormEventUtil_077 end";
}

/**
 * @tc.name: FormEventUtil_078
 * @tc.desc: Test SetTimerCfgByMultUpdate with all invalid entries, cfg unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_078, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_078 start";
    FormTimerCfg cfg = {};
    FormEventUtil::SetTimerCfgByMultUpdate("25:00,24:99", cfg);
    EXPECT_FALSE(cfg.enableUpdate);
    EXPECT_TRUE(cfg.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_078 end";
}

/**
 * @tc.name: FormEventUtil_079
 * @tc.desc: Test UpdateMultiUpdateTime with valid time string.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_079, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_079 start";
    FormRecord formRecord = {};
    FormEventUtil::UpdateMultiUpdateTime("8:0,18:30", formRecord);
    EXPECT_EQ(formRecord.updateAtTimes.size(), 2u);
    EXPECT_EQ(formRecord.updateAtTimes[0][0], 8);
    EXPECT_EQ(formRecord.updateAtTimes[0][1], 0);
    EXPECT_EQ(formRecord.updateAtTimes[1][0], 18);
    EXPECT_EQ(formRecord.updateAtTimes[1][1], 30);
    GTEST_LOG_(INFO) << "FormEventUtil_079 end";
}

/**
 * @tc.name: FormEventUtil_080
 * @tc.desc: Test UpdateMultiUpdateTime with invalid time, updateAtTimes remains empty.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_080, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_080 start";
    FormRecord formRecord = {};
    FormEventUtil::UpdateMultiUpdateTime("99:99", formRecord);
    EXPECT_TRUE(formRecord.updateAtTimes.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_080 end";
}

/**
 * @tc.name: FormEventUtil_081
 * @tc.desc: Test BuildFormInfos with empty records returns empty vector.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_081, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_081 start";
    std::vector<FormRecord> records;
    auto formInfos = FormEventUtil::BuildFormInfos(records);
    EXPECT_TRUE(formInfos.empty());
    GTEST_LOG_(INFO) << "FormEventUtil_081 end";
}

/**
 * @tc.name: FormEventUtil_082
 * @tc.desc: Test BuildFormInfos with records, return size matches input.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_082, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_082 start";
    std::vector<FormRecord> records;
    FormRecord record1;
    record1.formId = 1;
    record1.bundleName = FORM_HOST_BUNDLE_NAME;
    record1.moduleName = PARAM_PROVIDER_MODULE_NAME;
    record1.abilityName = FORM_PROVIDER_ABILITY_NAME;
    record1.formName = FORM_NAME;
    records.push_back(record1);
    FormRecord record2;
    record2.formId = 2;
    record2.bundleName = FORM_HOST_BUNDLE_NAME;
    record2.moduleName = PARAM_PROVIDER_MODULE_NAME;
    record2.abilityName = FORM_PROVIDER_ABILITY_NAME;
    record2.formName = FORM_NAME;
    records.push_back(record2);
    auto formInfos = FormEventUtil::BuildFormInfos(records);
    EXPECT_EQ(formInfos.size(), records.size());
    GTEST_LOG_(INFO) << "FormEventUtil_082 end";
}

}