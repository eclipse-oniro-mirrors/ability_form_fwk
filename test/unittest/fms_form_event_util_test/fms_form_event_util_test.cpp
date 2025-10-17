/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
extern void MockGetUidByBundleName(bool mockRet);
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
 * @tc.name: FormEventUtil_001
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_001 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int userId = 1;
    MockSetFormTempFlag(true);
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(false);
    MockGetBundlePackInfo(true);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_001 end";
}

/**
 * @tc.name: FormEventUtil_002
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_002 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int userId = 1;
    MockSetFormTempFlag(false);
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(false);
    MockGetBundlePackInfo(false);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_002 end";
}

/**
 * @tc.name: FormEventUtil_003
 * @tc.desc: test HandleProviderRemoved function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_003 start";
    std::string bundleName = "aa";
    int32_t userId = 2;
    MockGetMatchCount(true);
    FormEventUtil::HandleProviderRemoved(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_003 end";
}

/**
 * @tc.name: FormEventUtil_004
 * @tc.desc: test HandleProviderRemoved function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_004 start";
    std::string bundleName = "aa";
    int32_t userId = 2;
    MockGetMatchCount(false);
    FormEventUtil::HandleProviderRemoved(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_004 end";
}

/**
 * @tc.name: FormEventUtil_005
 * @tc.desc: test HandleBundleDataCleared function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_005 start";
    std::string bundleName = "aa";
    int32_t userId = 1;
    MockGetReCreateFormRecordsByBundleName(true);
    MockGetUidByBundleName(true);
    FormEventUtil::HandleBundleDataCleared(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_005 end";
}

/**
 * @tc.name: FormEventUtil_006
 * @tc.desc: test HandleBundleDataCleared function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_006 start";
    std::string bundleName = "aa";
    int32_t userId = 1;
    MockGetReCreateFormRecordsByBundleName(false);
    MockGetUidByBundleName(false);
    FormEventUtil::HandleBundleDataCleared(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_006 end";
}

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
 * @tc.name: FormEventUtil_012
 * @tc.desc: test ClearFormDBRecordData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_012 start";
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(false);
    MockGetNoHostDBFormsOne(false);
    FormEventUtil::ClearFormDBRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_012 end";
}

/**
 * @tc.name: FormEventUtil_013
 * @tc.desc: test ClearFormDBRecordData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_013 start";
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(false);
    MockGetNoHostDBFormsOne(true);
    FormEventUtil::ClearFormDBRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_013 end";
}

/**
 * @tc.name: FormEventUtil_014
 * @tc.desc: test ClearFormDBRecordData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_014 start";
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(true);
    MockGetNoHostDBFormsOne(true);
    FormEventUtil::ClearFormDBRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_014 end";
}

/**
 * @tc.name: FormEventUtil_015
 * @tc.desc: test ClearTempFormRecordData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_015 start";
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostTempFormsOne(false);
    MockGetNoHostTempFormsTwo(false);
    FormEventUtil::ClearTempFormRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_015 end";
}

/**
 * @tc.name: FormEventUtil_016
 * @tc.desc: test ClearTempFormRecordData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventUtil_016 start";
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostTempFormsOne(true);
    MockGetNoHostTempFormsTwo(true);
    FormEventUtil::ClearTempFormRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_016 end";
}

/**
 * @tc.name: FormEventUtil_017
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_017 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(false);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_017 end";
}

/**
 * @tc.name: FormEventUtil_018
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_018 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(false);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_018 end";
}

/**
 * @tc.name: FormEventUtil_019
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_019 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(true);
    MockGetBundlePackInfo(true);
    MockGetUpdatedForm(true);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_019 end";
}

/**
 * @tc.name: FormEventUtil_020
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_020 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(true);
    MockGetBundlePackInfo(true);
    MockGetUpdatedForm(false);
    MockGetPackageForm(true);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_020 end";
}

/**
 * @tc.name: FormEventUtil_021
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_021 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(true);
    MockGetBundlePackInfo(true);
    MockGetUpdatedForm(false);
    MockGetPackageForm(false);
    MockSetFormTempFlag(true);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_021 end";
}

/**
 * @tc.name: FormEventUtil_022
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_022 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(true);
    MockGetBundlePackInfo(false);
    MockGetUpdatedForm(false);
    MockGetPackageForm(true);
    MockSetFormTempFlag(false);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_022 end";
}

/**
 * @tc.name: FormEventUtil_023
 * @tc.desc: test HandleProviderUpdated function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_023 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(true);
    MockGetBundlePackInfo(true);
    MockGetUpdatedForm(true);
    FormEventUtil::HandleProviderUpdated(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_023 end";
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
 * @tc.name: FormEventUtil_025
 * @tc.desc: test HandleBundleFormInfoRemoved function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_025 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int32_t userId = 1;
    FormEventUtil::HandleBundleFormInfoRemoved(bundleName, userId);
    GTEST_LOG_(INFO) << "FormEventUtil_025 end";
}

/**
 * @tc.name: FormEventUtil_026
 * @tc.desc: test HandleFormHostDataCleared function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_026 start";
    int32_t userId = 1;
    MockGetNoHostDBFormsTwo(true);
    MockGetNoHostDBFormsOne(true);
    MockGetNoHostTempFormsOne(true);
    MockGetNoHostTempFormsTwo(true);
    FormEventUtil::HandleFormHostDataCleared(userId);
    GTEST_LOG_(INFO) << "FormEventUtil_026 end";
}

/**
 * @tc.name: FormEventUtil_027
 * @tc.desc: test BatchDeleteNoHostTempForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_027 start";
    int32_t userId = 1;
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    int64_t formIds[2] = { 1, 2 };
    std::string bundleName[2] = { "com.form.start", "com.form.start2" };
    std::string abilityName[2] = { "bbbbbb", "bbbbbb2" };
    for (int32_t i = 0; i < 2; ++i) {
        FormIdKey formIdKey(bundleName[i], abilityName[i]);
        std::set<int64_t> formIdsSet;
        bool flag = (i == 1);
        foundFormsMap.emplace(formIds[i], flag);
        formIdsSet.emplace(formIds[i]);
        noHostTempFormsMap.emplace(formIdKey, formIdsSet);
    }
    MockNotifyProviderFormsBatchDelete(true);
    FormEventUtil::BatchDeleteNoHostTempForms(userId, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_027 end";
}

/**
 * @tc.name: FormEventUtil_028
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_028 start";
    const bool updateEnabled = false;
    int32_t updateDuration = 1;
    const std::string configUpdataAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_028 end";
}

/**
 * @tc.name: FormEventUtil_029
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_029 start";
    const bool updateEnabled = true;
    int32_t updateDuration = static_cast<int32_t>(Constants::MIN_CONFIG_DURATION);
    const std::string configUpdataAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_029 end";
}

/**
 * @tc.name: FormEventUtil_030
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_030 start";
    const bool updateEnabled = true;
    int32_t updateDuration = static_cast<int32_t>(Constants::MAX_CONFIG_DURATION);
    const std::string configUpdataAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_030 end";
}

/**
 * @tc.name: FormEventUtil_031
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_031 start";
    const bool updateEnabled = true;
    int32_t updateDuration = static_cast<int32_t>(Constants::MIN_CONFIG_DURATION) + 1;
    const std::string configUpdataAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_031 end";
}

/**
 * @tc.name: FormEventUtil_032
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_032 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_032 end";
}

/**
 * @tc.name: FormEventUtil_033
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_033 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "17:41:41";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_033 end";
}

/**
 * @tc.name: FormEventUtil_034
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_034 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "17:41";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_034 end";
}

/**
 * @tc.name: FormEventUtil_035
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_035 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "-1:41";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_035 end";
}

/**
 * @tc.name: FormEventUtil_036
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_036 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "25:41";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_036 end";
}

/**
 * @tc.name: FormEventUtil_037
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_037 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "18:-1";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_037 end";
}

/**
 * @tc.name: FormEventUtil_038
 * @tc.desc: test GetTimerCfg function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_038 start";
    const bool updateEnabled = true;
    int32_t updateDuration = -1;
    const std::string configUpdataAt = "18:61";
    FormTimerCfg cfg = {};
    FormEventUtil::GetTimerCfg(updateEnabled, updateDuration, configUpdataAt, cfg);
    GTEST_LOG_(INFO) << "FormEventUtil_038 end";
}

/**
 * @tc.name: FormEventUtil_039
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_039, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_039 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = false;
    timerCfg.enableUpdate = false;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_039 end";
}

/**
 * @tc.name: FormEventUtil_040
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_040, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_040 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = false;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_040 end";
}

/**
 * @tc.name: FormEventUtil_041
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_041, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_041 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = false;
    timerCfg.enableUpdate = true;
    timerCfg.updateDuration = 1;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_041 end";
}

/**
 * @tc.name: FormEventUtil_042
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_042, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_042 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = false;
    timerCfg.enableUpdate = true;
    timerCfg.updateDuration = 0;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_042 end";
}

/**
 * @tc.name: FormEventUtil_043
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_043, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_043 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 1;
    timerCfg.updateDuration = 1;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_043 end";
}

/**
 * @tc.name: FormEventUtil_044
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_044, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_044 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 1;
    timerCfg.updateDuration = 2;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_044 end";
}

/**
 * @tc.name: FormEventUtil_045
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_045, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_045 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 1;
    timerCfg.updateDuration = 0;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_045 end";
}

/**
 * @tc.name: FormEventUtil_046
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_046, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_046 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 0;
    timerCfg.updateDuration = 0;
    record.updateAtHour = 0;
    timerCfg.updateAtHour = 0;
    record.updateAtMin = 0;
    timerCfg.updateAtMin = 0;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_046 end";
}

/**
 * @tc.name: FormEventUtil_047
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_047, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_047 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 0;
    timerCfg.updateDuration = 0;
    record.updateAtHour = 1;
    timerCfg.updateAtHour = 0;
    record.updateAtMin = 0;
    timerCfg.updateAtMin = 0;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_047 end";
}

/**
 * @tc.name: FormEventUtil_048
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_048, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_048 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 0;
    timerCfg.updateDuration = 0;
    record.updateAtHour = 0;
    timerCfg.updateAtHour = 0;
    record.updateAtMin = 1;
    timerCfg.updateAtMin = 0;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_048 end";
}

/**
 * @tc.name: FormEventUtil_049
 * @tc.desc: test HandleTimerUpdate function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_049, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_049 start";
    const int64_t formId = 1;
    FormRecord record = {};
    FormTimerCfg timerCfg = {};
    record.isEnableUpdate = true;
    timerCfg.enableUpdate = true;
    record.updateDuration = 0;
    timerCfg.updateDuration = 1;
    FormEventUtil::HandleTimerUpdate(formId, record, timerCfg);
    GTEST_LOG_(INFO) << "FormEventUtil_049 end";
}

/**
 * @tc.name: FormEventUtil_050
 * @tc.desc: test ReCreateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_050, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_050 start";
    const int64_t formId = 1;
    MockGetFormRecord(false);
    FormEventUtil::ReCreateForm(formId);
    GTEST_LOG_(INFO) << "FormEventUtil_050 end";
}

/**
 * @tc.name: FormEventUtil_051
 * @tc.desc: test ReCreateForm function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_051, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_051 start";
    const int64_t formId = 1;
    MockGetFormRecord(true);
    FormEventUtil::ReCreateForm(formId);
    GTEST_LOG_(INFO) << "FormEventUtil_051 end";
}

/**
 * @tc.name: FormEventUtil_052
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_052, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_052 start";
    int32_t userId = 1;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    std::map<int64_t, bool> removedFormsMap;
    int64_t formIds[2] = { 1, 2 };
    std::string bundleName[2] = { "com.form.start", "com.form.start2" };
    std::string moduleName[2] = { "bbbbbb", "bbbbbb2" };
    for (int32_t i = 0; i < 2; ++i) {
        FormIdKey formIdKey(bundleName[i], moduleName[i]);
        std::set<int64_t> formIdsSet;
        bool flag = (i == 1);
        removedFormsMap.emplace(formIds[i], flag);
        formIdsSet.emplace(formIds[i]);
        noHostFormDbMap.emplace(formIdKey, formIdsSet);
    }
    MockNotifyProviderFormsBatchDelete(false);
    FormEventUtil::BatchDeleteNoHostDBForms(userId, noHostFormDbMap, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_052 end";
}

/**
 * @tc.name: FormEventUtil_053
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_053, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_053 start";
    int32_t userId = 1;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    std::map<int64_t, bool> removedFormsMap;
    int64_t formIds[2] = { 1, 2 };
    std::string bundleName[2] = { "com.form.start", "com.form.start2" };
    std::string moduleName[2] = { "bbbbbb", "bbbbbb2" };
    for (int32_t i = 0; i < 2; ++i) {
        FormIdKey formIdKey(bundleName[i], moduleName[i]);
        std::set<int64_t> formIdsSet;
        bool flag = (i == 1);
        removedFormsMap.emplace(formIds[i], flag);
        formIdsSet.emplace(formIds[i]);
        noHostFormDbMap.emplace(formIdKey, formIdsSet);
    }
    MockNotifyProviderFormsBatchDelete(true);
    MockGetMatchCount(false);
    FormEventUtil::BatchDeleteNoHostDBForms(userId, noHostFormDbMap, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_053 end";
}

/**
 * @tc.name: FormEventUtil_054
 * @tc.desc: test BatchDeleteNoHostDBForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_054, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_054 start";
    int32_t userId = 1;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    std::map<int64_t, bool> removedFormsMap;
    int64_t formIds[2] = { 1, 2 };
    std::string bundleName[2] = { "com.form.start", "com.form.start2" };
    std::string moduleName[2] = { "bbbbbb", "bbbbbb2" };
    for (int32_t i = 0; i < 2; ++i) {
        FormIdKey formIdKey(bundleName[i], moduleName[i]);
        std::set<int64_t> formIdsSet;
        bool flag = (i == 1);
        removedFormsMap.emplace(formIds[i], flag);
        formIdsSet.emplace(formIds[i]);
        noHostFormDbMap.emplace(formIdKey, formIdsSet);
    }
    MockNotifyProviderFormsBatchDelete(true);
    MockGetMatchCount(true);
    FormEventUtil::BatchDeleteNoHostDBForms(userId, noHostFormDbMap, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_054 end";
}

/**
 * @tc.name: FormEventUtil_055
 * @tc.desc: test BatchDeleteNoHostTempForms function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_055, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_055 start";
    int32_t userId = 1;
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    int64_t formIds[2] = { 1, 2 };
    std::string bundleName[2] = { "com.form.start", "com.form.start2" };
    std::string abilityName[2] = { "bbbbbb", "bbbbbb2" };
    for (int32_t i = 0; i < 2; ++i) {
        FormIdKey formIdKey(bundleName[i], abilityName[i]);
        std::set<int64_t> formIdsSet;
        bool flag = (i == 1);
        foundFormsMap.emplace(formIds[i], flag);
        formIdsSet.emplace(formIds[i]);
        noHostTempFormsMap.emplace(formIdKey, formIdsSet);
    }
    MockNotifyProviderFormsBatchDelete(false);
    FormEventUtil::BatchDeleteNoHostTempForms(userId, noHostTempFormsMap, foundFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_055 end";
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
 * @tc.name: FormEventUtil_058
 * @tc.desc: test HandleUpdateFormCloud function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventUtilTest, FormEventUtil_058, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormEventUtil_058 start";
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    FormEventUtil::HandleUpdateFormCloud(bundleName);
    GTEST_LOG_(INFO) << "FormEventUtil_058 end";
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
}