/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "form_data_mgr.h"
#include "form_event_util.h"
#undef private
#include "mock_form_provider_client.h"
#include "ipc_types.h"
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
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
    FormEventUtil formEventUtil;
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int userId = 1;
    MockSetFormTempFlag(true);
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(false);
    MockGetBundlePackInfo(true);
    formEventUtil.HandleProviderUpdated(bundleName, userId);
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
    FormEventUtil formEventUtil;
    std::string bundleName = FORM_HOST_BUNDLE_NAME;
    int userId = 1;
    MockSetFormTempFlag(false);
    MockGetFormRecord(true);
    MockGetFormsInfoByBundle(false);
    MockGetBundlePackInfo(false);
    formEventUtil.HandleProviderUpdated(bundleName, userId);
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
    FormEventUtil formEventUtil;
    std::string bundleName = "aa";
    int32_t userId = 2;
    MockGetMatchCount(true);
    formEventUtil.HandleProviderRemoved(bundleName, userId);
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
    FormEventUtil formEventUtil;
    std::string bundleName = "aa";
    int32_t userId = 2;
    MockGetMatchCount(false);
    formEventUtil.HandleProviderRemoved(bundleName, userId);
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
    FormEventUtil formEventUtil;
    std::string bundleName = "aa";
    int32_t userId = 1;
    MockGetReCreateFormRecordsByBundleName(true);
    MockGetUidByBundleName(true);
    formEventUtil.HandleBundleDataCleared(bundleName, userId);
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
    FormEventUtil formEventUtil;
    std::string bundleName = "aa";
    int32_t userId = 1;
    MockGetReCreateFormRecordsByBundleName(false);
    MockGetUidByBundleName(false);
    formEventUtil.HandleBundleDataCleared(bundleName, userId);
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
    FormEventUtil formEventUtil;
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    EXPECT_EQ(false, formEventUtil.ProviderFormUpdated(formId, formRecord, targetForms));
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
    FormEventUtil formEventUtil;
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    targetForms.emplace_back(formInfo);
    MockGetUpdatedForm(false);
    EXPECT_EQ(false, formEventUtil.ProviderFormUpdated(formId, formRecord, targetForms));
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
    FormEventUtil formEventUtil;
    int64_t formId = 1;
    FormRecord formRecord;
    std::vector<FormInfo> targetForms;
    FormInfo formInfo;
    formInfo.bundleName = FORM_HOST_BUNDLE_NAME;
    formInfo.moduleName = PARAM_PROVIDER_MODULE_NAME;
    formInfo.abilityName = FORM_PROVIDER_ABILITY_NAME;
    formInfo.name = FORM_NAME;
    targetForms.emplace_back(formInfo);
    MockGetUpdatedForm(true);
    EXPECT_EQ(true, formEventUtil.ProviderFormUpdated(formId, formRecord, targetForms));
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
    FormEventUtil formEventUtil;
    int64_t formId = 1;
    FormRecord formRecord;
    BundlePackInfo bundlePackInfo;
    MockGetPackageForm(false);
    EXPECT_EQ(false, formEventUtil.ProviderFormUpdated(formId, formRecord, bundlePackInfo));
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
    FormEventUtil formEventUtil;
    int64_t formId = 1;
    FormRecord formRecord;
    BundlePackInfo bundlePackInfo;
    MockGetPackageForm(true);
    EXPECT_EQ(true, formEventUtil.ProviderFormUpdated(formId, formRecord, bundlePackInfo));
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
    FormEventUtil formEventUtil;
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(false);
    MockGetNoHostDBFormsOne(false);
    formEventUtil.ClearFormDBRecordData(uid, removedFormsMap);
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
    FormEventUtil formEventUtil;
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(false);
    MockGetNoHostDBFormsOne(true);
    formEventUtil.ClearFormDBRecordData(uid, removedFormsMap);
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
    FormEventUtil formEventUtil;
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostDBFormsTwo(true);
    MockGetNoHostDBFormsOne(true);
    formEventUtil.ClearFormDBRecordData(uid, removedFormsMap);
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
    FormEventUtil formEventUtil;
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostTempFormsOne(false);
    MockGetNoHostTempFormsTwo(false);
    formEventUtil.ClearTempFormRecordData(uid, removedFormsMap);
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
    FormEventUtil formEventUtil;
    int uid = 1;
    std::map<int64_t, bool> removedFormsMap;
    MockGetNoHostTempFormsOne(true);
    MockGetNoHostTempFormsTwo(true);
    formEventUtil.ClearTempFormRecordData(uid, removedFormsMap);
    GTEST_LOG_(INFO) << "FormEventUtil_016 end";
}
}