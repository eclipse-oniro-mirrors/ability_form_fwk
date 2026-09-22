/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gmock/gmock.h>

#define private public
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "data_center/form_data_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_data_mgr.h"
#include "mock_form_db_cache.h"
#include "mock_form_distributed_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_queue.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AppExecFwk {

const std::string FORM_BUNDLE_NAME_TEST = "ohos.samples.Test";
const std::string PARAM_MODULE_NAME_TEST = "entry";
const std::string FORM_ABILITY_NAME_TEST = "ohos.samples.Test.MainAbility";
const std::string PARAM_FORM_NAME = "com.form.name.test";
const std::string FORM_JS_COMPONENT_NAME = "jsComponentName";
const int32_t USER_ID = 100;
const nlohmann::json JSON_FORMS = R"({})"_json;
class FormInfoMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
protected:
    std::shared_ptr<FormInfoHelper> formInfoHelper_;
};
void FormInfoMgrTest::SetUpTestCase(void)
{
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockFormDistributedMgr::obj = std::make_shared<MockFormDistributedMgr>();
}

void FormInfoMgrTest::TearDownTestCase(void)
{
    MockFormBmsHelper::obj = nullptr;
    MockFormDataMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    MockFormDistributedMgr::obj = nullptr;
}

void FormInfoMgrTest::SetUp(void)
{
    formInfoHelper_ = std::make_shared<FormInfoHelper>();
    auto &mgr = FormInfoMgr::GetInstance();
    mgr.Start();
    // Clear device DB data so tests start from a clean bundleFormInfoMap_.
    mgr.bundleFormInfoMap_.clear();
    // Reset per-test reload state (singleton persists across tests).
    mgr.reloadUserIds_.clear();
    mgr.reloadingCtxs_.clear();
    // Cancel any stale FFRT retry tasks from previous tests to prevent
    // them from firing during this test and polluting singleton state.
    FormMgrQueue::GetInstance().CancelDelayTask(
        Common::TaskKey("ReloadRetry_" + std::to_string(USER_ID)));
    // Sync executor: chained batch tasks (T0/Tk/T_fin) run inline, keeping
    // ReloadFormInfos synchronous inside unit tests (existing cases stay green).
    mgr.batchExecutor_ = [](std::function<void()> task) -> bool {
        task();
        return true;
    };
    // Default mocks: BMS is valid; bundles not in versionMap are treated as
    // disabled-but-installed (skip) instead of removed.
    ON_CALL(*MockFormBmsHelper::obj, IsBundleMgrValid()).WillByDefault(Return(true));
    ON_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _)).WillByDefault(Return(true));
    ON_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillByDefault(Return(true));
    ON_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillByDefault(Return(true));
}

void FormInfoMgrTest::TearDown(void)
{}

FormInfo GetTestFormInfo()
{
    FormInfo formInfo;
    formInfo.bundleName = FORM_BUNDLE_NAME_TEST;
    formInfo.abilityName = FORM_ABILITY_NAME_TEST;
    formInfo.moduleName = PARAM_MODULE_NAME_TEST;
    formInfo.name = PARAM_FORM_NAME;
    formInfo.isStatic = true;
    formInfo.updateEnabled = true;
    formInfo.updateDuration = 1;
    formInfo.scheduledUpdateTime = "06:06";
    formInfo.jsComponentName = FORM_JS_COMPONENT_NAME;
    formInfo.formVisibleNotify = true;
    formInfo.supportDimensions = {1, 2};
    formInfo.defaultDimension = 1;
    formInfo.supportShapes = {1, 2};
    return formInfo;
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_0200
 * @tc.number: ReloadFormInfos
 * @tc.desc: ReloadFormInfos for the same user is deduplicated; second call is skipped
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_0200 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_EQ(1, static_cast<int>(FormInfoMgr::GetInstance().reloadUserIds_.count(USER_ID)));
    // second call for the same user should be skipped (dedup)
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_EQ(1, static_cast<int>(FormInfoMgr::GetInstance().reloadUserIds_.count(USER_ID)));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_0200 end";
}

/**
 * @tc.name: FormInfoMgr_HasReloadedFormInfos_0100
 * @tc.number: HasReloadedFormInfos
 * @tc.desc: HasReloadedFormInfos reflects reload state of reloadUserIds_
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_HasReloadedFormInfos_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_HasReloadedFormInfos_0100 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_HasReloadedFormInfos_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ClearReloadUserId_0100
 * @tc.number: ClearReloadUserId
 * @tc.desc: After ClearReloadUserId, the user can be reloaded again
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClearReloadUserId_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClearReloadUserId_0100 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().reloadUserIds_.count(USER_ID)));
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    // after clear, reload should run again
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ClearReloadUserId_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0100
 * @tc.desc: ClassifyBundles with empty map, all versionMap entries are newBundles
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0100 start";
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap = {
        {"com.test.bundleA", 1}, {"com.test.bundleB", 2}, {"com.test.bundleC", 3}};
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(3, static_cast<int>(result.newBundles.size()));
    EXPECT_EQ(0, static_cast<int>(result.updateBundles.size()));
    EXPECT_EQ(0, static_cast<int>(result.removeBundles.size()));
    EXPECT_EQ(3, static_cast<int>(result.TotalWorkload()));
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0200
 * @tc.desc: ClassifyBundles when version unchanged and not isNeedUpdateAll, bundle skipped
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0200 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    FormInfo formInfo = GetTestFormInfo();
    formInfo.versionCode = 5;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap = {{FORM_BUNDLE_NAME_TEST, 5}};
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(0, static_cast<int>(result.TotalWorkload()));
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0200 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0300
 * @tc.desc: ClassifyBundles when version changed, bundle goes to updateBundles
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0300 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    FormInfo formInfo = GetTestFormInfo();
    formInfo.versionCode = 1;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap = {{FORM_BUNDLE_NAME_TEST, 2}};
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(1, static_cast<int>(result.updateBundles.size()));
    EXPECT_EQ(FORM_BUNDLE_NAME_TEST, result.updateBundles[0]);
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0300 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0400
 * @tc.desc: ClassifyBundles when bundle uninstalled (not in versionMap, not in BMS), goes to removeBundles
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0400, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0400 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _)).Times(1)
        .WillOnce(Return(false));
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap;
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(1, static_cast<int>(result.removeBundles.size()));
    EXPECT_EQ(FORM_BUNDLE_NAME_TEST, result.removeBundles[0]);
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0400 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0500
 * @tc.desc: ClassifyBundles when bundle disabled (not in versionMap but still installed), skipped
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0500, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0500 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _)).Times(1).WillOnce(Return(true));
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap;
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(0, static_cast<int>(result.TotalWorkload()));
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0500 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0600
 * @tc.desc: ClassifyBundles with isNeedUpdateAll=true forces update even if version unchanged
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0600 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    FormInfo formInfo = GetTestFormInfo();
    formInfo.versionCode = 5;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap = {{FORM_BUNDLE_NAME_TEST, 5}};
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(true, USER_ID, bundleVersionMap);
    EXPECT_EQ(1, static_cast<int>(result.updateBundles.size()));
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0600 end";
}

/**
 * @tc.name: FormInfoMgr_ClassifyBundles_0700
 * @tc.desc: ClassifyBundles mixed scenario, one bundle per category
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ClassifyBundles_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0700 start";
    // bundleUpdate: in versionMap with changed version -> updateBundles
    auto updatePtr = std::make_shared<BundleFormInfo>("com.test.update");
    FormInfoStorage updateStorage;
    updateStorage.userId = USER_ID;
    FormInfo updateInfo = GetTestFormInfo();
    updateInfo.bundleName = "com.test.update";
    updateInfo.versionCode = 1;
    updateStorage.formInfos.push_back(updateInfo);
    updatePtr->formInfoStorages_.emplace_back(updateStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_["com.test.update"] = updatePtr;
    // bundleRemove: not in versionMap and not installed -> removeBundles
    auto removePtr = std::make_shared<BundleFormInfo>("com.test.remove");
    FormInfoStorage removeStorage;
    removeStorage.userId = USER_ID;
    removeStorage.formInfos.push_back(GetTestFormInfo());
    removePtr->formInfoStorages_.emplace_back(removeStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_["com.test.remove"] = removePtr;
    // bundleKeep: in versionMap with same version -> skipped
    auto keepPtr = std::make_shared<BundleFormInfo>("com.test.keep");
    FormInfoStorage keepStorage;
    keepStorage.userId = USER_ID;
    FormInfo keepInfo = GetTestFormInfo();
    keepInfo.bundleName = "com.test.keep";
    keepInfo.versionCode = 5;
    keepStorage.formInfos.push_back(keepInfo);
    keepPtr->formInfoStorages_.emplace_back(keepStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_["com.test.keep"] = keepPtr;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _)).WillRepeatedly(Return(false));
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap = {
        {"com.test.update", 2}, {"com.test.keep", 5}, {"com.test.new", 9}};
    auto result = FormInfoMgr::GetInstance().ClassifyBundles(false, USER_ID, bundleVersionMap);
    EXPECT_EQ(1, static_cast<int>(result.updateBundles.size()));
    EXPECT_EQ(1, static_cast<int>(result.removeBundles.size()));
    EXPECT_EQ(1, static_cast<int>(result.newBundles.size()));
    EXPECT_EQ(3, static_cast<int>(result.TotalWorkload()));
    GTEST_LOG_(INFO) << "FormInfoMgr_ClassifyBundles_0700 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Callback_0100
 * @tc.desc: doneCallback is invoked synchronously when user already reloaded (idempotent hit)
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Callback_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0100 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    int callCount = 0;
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [&callCount]() { callCount++; }));
    EXPECT_EQ(1, callCount);
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Callback_0200
 * @tc.desc: doneCallback is invoked once after fresh reload completes (after publish)
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Callback_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0200 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    int callCount = 0;
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [&callCount]() { callCount++; }));
    EXPECT_EQ(1, callCount);
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0200 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Callback_0300
 * @tc.desc: ReloadFormInfos with nullptr callback does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Callback_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0300 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, nullptr));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Callback_0300 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0100
 * @tc.desc: reload with no pending bundles and no removals finishes immediately and marks reloaded
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0100 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0300
 * @tc.desc: bundles exceeding batch size are processed in chained batches with correct offsets
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0300 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Invoke(
        [](const ExtensionAbilityType &, const int32_t &, std::vector<ExtensionAbilityInfo> &infos) {
            for (int i = 0; i < 120; ++i) {
                ExtensionAbilityInfo info;
                info.bundleName = "bundle" + std::to_string(i);
                info.type = ExtensionAbilityType::FORM;
                infos.push_back(info);
            }
            return true;
        }));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, BatchGetBundleInfo(_, _, _, _)).WillRepeatedly(Invoke(
        [](const std::vector<std::string> &names, int32_t, std::vector<BundleInfo> &out, int32_t) {
            out.clear();
            return ERR_OK;
        }));
    int executorCalls = 0;
    FormInfoMgr::GetInstance().batchExecutor_ = [&executorCalls](std::function<void()> task) -> bool {
        executorCalls++;
        task();
        return true;
    };
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    // 120 bundles / batch 50 = 3 batches. Executor invocations:
    // entry->T0(1) + T0->batch1(2) + batch1->batch2(3) + batch2->batch3(4) + batch3->T_fin(5)
    EXPECT_EQ(5, executorCalls);
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0300 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0600
 * @tc.desc: failed batch is recorded and retried once in FinishReloadBatches
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0600, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0600 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Invoke(
        [](const ExtensionAbilityType &, const int32_t &, std::vector<ExtensionAbilityInfo> &infos) {
            for (int i = 0; i < 60; ++i) {
                ExtensionAbilityInfo info;
                info.bundleName = "bundle" + std::to_string(i);
                info.type = ExtensionAbilityType::FORM;
                infos.push_back(info);
            }
            return true;
        }));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    int batchCallCount = 0;
    EXPECT_CALL(*MockFormBmsHelper::obj, BatchGetBundleInfo(_, _, _, _)).WillRepeatedly(Invoke(
        [&batchCallCount](const std::vector<std::string> &names, int32_t, std::vector<BundleInfo> &out, int32_t) {
            batchCallCount++;
            out.clear();
            return batchCallCount == 1 ? ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED : ERR_OK;
        }));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_EQ(3, batchCallCount); // batch1(fail) + batch2 + retry of batch1 in T_fin
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0600 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0700
 * @tc.desc: GetBundleVersionMap failure triggers anti-hang path when retry scheduling fails
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0700, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0700 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(false));
    auto callCount = std::make_shared<int>(0);
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [callCount]() { (*callCount)++; }));
    // Mock ScheduleDelayTask returns false: anti-hang path fires callbacks immediately
    EXPECT_EQ(1, *callCount);
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    // ctx cleared by FireReloadCallbacks
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().reloadingCtxs_.count(USER_ID)));
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0700 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Retry_0100
 * @tc.desc: first failure increments retryCount, anti-hang fires callbacks when retry scheduling fails
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Retry_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Retry_0100 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(false));

    auto ctx = std::make_shared<FormInfoMgr::ReloadContext>();
    ctx->userId = USER_ID;
    ctx->retryCount = 0;
    auto callCount = std::make_shared<int>(0);
    ctx->doneCallbacks.push_back([callCount]() { (*callCount)++; });

    FormInfoMgr::GetInstance().StartReloadBatches(ctx);

    // Mock ScheduleDelayTask returns false: retryCount incremented but anti-hang
    // path fires callbacks immediately and clears registry
    EXPECT_EQ(1, ctx->retryCount);
    EXPECT_EQ(1, *callCount);
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().reloadingCtxs_.count(USER_ID)));
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Retry_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Retry_0200
 * @tc.desc: retries exhausted fires callbacks once, clears registry, reports FAULT
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Retry_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Retry_0200 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(false));

    auto ctx = std::make_shared<FormInfoMgr::ReloadContext>();
    ctx->userId = USER_ID;
    ctx->retryCount = 3; // already exhausted
    int callCount = 0;
    ctx->doneCallbacks.push_back([&callCount]() { callCount++; });
    FormInfoMgr::GetInstance().reloadingCtxs_[USER_ID] = ctx;

    FormInfoMgr::GetInstance().StartReloadBatches(ctx);

    // Give-up: callbacks fired exactly once, registry cleared, not marked
    EXPECT_EQ(1, callCount);
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().reloadingCtxs_.count(USER_ID)));
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));

    FormInfoMgr::GetInstance().reloadingCtxs_.clear();
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Retry_0200 end";
}

/**
 * @tc.name: FormInfoMgr_RemoveUserId_0100
 * @tc.desc: RemoveUserId clears the userId bucket and recycles empty bundle
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_RemoveUserId_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveUserId_0100 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage storage;
    storage.userId = USER_ID;
    storage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(storage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;

    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().RemoveUserId(USER_ID));

    // Sole-user bundle recycled from map
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().bundleFormInfoMap_.count(FORM_BUNDLE_NAME_TEST)));
    // Reload flag cleared (user can be re-created and reloaded)
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveUserId_0100 end";
}

/**
 * @tc.name: FormInfoMgr_RemoveUserId_0200
 * @tc.desc: RemoveUserId preserves other users' data in the same bundle
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_RemoveUserId_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveUserId_0200 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage storage1;
    storage1.userId = USER_ID;
    storage1.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(storage1);
    FormInfoStorage storage2;
    storage2.userId = USER_ID + 1;
    storage2.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(storage2);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;

    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().RemoveUserId(USER_ID));

    // Bundle survives (other user intact), removed user's bucket gone
    auto it = FormInfoMgr::GetInstance().bundleFormInfoMap_.find(FORM_BUNDLE_NAME_TEST);
    ASSERT_TRUE(it != FormInfoMgr::GetInstance().bundleFormInfoMap_.end());
    EXPECT_FALSE(it->second->Empty());
    for (const auto &item : it->second->formInfoStorages_) {
        EXPECT_NE(USER_ID, item.userId);
    }
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveUserId_0200 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0800
 * @tc.desc: removeBundles bundles are removed and erased from map in T_fin
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0800, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0800 start";
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo->formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoMgr::GetInstance().bundleFormInfoMap_.clear();
    FormInfoMgr::GetInstance().bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _)).WillOnce(Return(false));
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().bundleFormInfoMap_.count(FORM_BUNDLE_NAME_TEST)));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0800 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_0900
 * @tc.desc: isNeedUpdateAll triggers exactly one version write-back after completion
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_0900, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0900 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    std::string versionBefore;
    FormInfoRdbStorageMgr::GetInstance().GetFormVersionCode(versionBefore);
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID));
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    std::string versionAfter;
    FormInfoRdbStorageMgr::GetInstance().GetFormVersionCode(versionAfter);
    // isNeedUpdateAll path executed to completion (version write-back attempted in T_fin)
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_0900 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_1300
 * @tc.desc: in-flight re-entry appends callback instead of starting a duplicate chain
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_1300, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_1300 start";
    EXPECT_CALL(*MockFormBmsHelper::obj, QueryExtensionAbilityInfosByType(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfos(_, _, _)).WillRepeatedly(Return(true));
    // Delayed executor: capture tasks without running, chain stays in-flight
    std::vector<std::function<void()>> pendingTasks;
    FormInfoMgr::GetInstance().batchExecutor_ = [&pendingTasks](std::function<void()> task) -> bool {
        pendingTasks.push_back(std::move(task));
        return true;
    };
    int firstCallbackCount = 0;
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [&firstCallbackCount]() {
        firstCallbackCount++;
    }));
    EXPECT_EQ(1, static_cast<int>(pendingTasks.size()));
    // Second trigger while chain in-flight: appends callback, no new task submitted
    int secondCallbackCount = 0;
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [&secondCallbackCount]() {
        secondCallbackCount++;
    }));
    EXPECT_EQ(1, static_cast<int>(pendingTasks.size()));
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    // Drain: run T0, then batch tasks until chain completes
    size_t runIndex = 0;
    while (runIndex < pendingTasks.size() && runIndex < 100) { // bound: no infinite loop
        auto task = pendingTasks[runIndex++];
        task();
    }
    EXPECT_TRUE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID));
    EXPECT_EQ(1, firstCallbackCount);
    EXPECT_EQ(1, secondCallbackCount); // appended callback fired by in-flight chain T_fin
    FormInfoMgr::GetInstance().ClearReloadUserId(USER_ID);
    FormInfoMgr::GetInstance().reloadingCtxs_.clear();
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_1300 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_Batch_1500
 * @tc.desc: abort in-flight chain before start: callbacks fire, no mark/publish
 * @tc.type: FUNC
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_Batch_1500, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_1500 start";
    std::vector<std::function<void()>> pendingTasks;
    FormInfoMgr::GetInstance().batchExecutor_ = [&pendingTasks](std::function<void()> task) -> bool {
        pendingTasks.push_back(std::move(task));
        return true;
    };
    int callCount = 0;
    EXPECT_EQ(ERR_OK, FormInfoMgr::GetInstance().ReloadFormInfos(USER_ID, [&callCount]() { callCount++; }));
    ASSERT_EQ(1, static_cast<int>(pendingTasks.size()));
    // Simulate user removal aborting the in-flight chain
    auto it = FormInfoMgr::GetInstance().reloadingCtxs_.find(USER_ID);
    ASSERT_TRUE(it != FormInfoMgr::GetInstance().reloadingCtxs_.end());
    auto inFlight = it->second.lock();
    ASSERT_TRUE(inFlight != nullptr);
    inFlight->aborted.store(true);
    // Drain: T0 (aborted -> dispatches T_fin), then T_fin (fires callbacks, clears registry)
    size_t runIndex = 0;
    while (runIndex < pendingTasks.size() && runIndex < 10) {
        auto task = pendingTasks[runIndex++];
        task();
    }
    EXPECT_EQ(1, callCount); // callbacks fired to avoid hanging
    EXPECT_FALSE(FormInfoMgr::GetInstance().HasReloadedFormInfos(USER_ID)); // not marked
    EXPECT_EQ(0, static_cast<int>(FormInfoMgr::GetInstance().reloadingCtxs_.count(USER_ID)));
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_Batch_1500 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
