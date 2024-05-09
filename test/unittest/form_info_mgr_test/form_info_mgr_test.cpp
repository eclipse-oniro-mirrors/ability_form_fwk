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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#include "form_bms_helper.h"
#include "form_info_mgr.h"
#include "mock_bundle_mgr.h"
#undef private
#include "form_mgr_errors.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

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
    FormInfoMgr formInfoMgr_;
};
void FormInfoMgrTest::SetUpTestCase(void)
{}

void FormInfoMgrTest::TearDownTestCase(void)
{}

void FormInfoMgrTest::SetUp(void)
{
    formInfoHelper_ = std::make_shared<FormInfoHelper>();
    formInfoMgr_.Start();
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

FormInfo GetTestCircleFormInfo()
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
    formInfo.supportShapes = {2};
    return formInfo;
}

/**
 * @tc.name: FormInfoHelper_LoadFormConfigInfoByBundleName_0100
 * @tc.number: LoadFormConfigInfoByBundleName
 * @tc.desc: call LoadFormConfigInfoByBundleName with wrong userId
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_LoadFormConfigInfoByBundleName_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadFormConfigInfoByBundleName_0100 start";
    std::vector<FormInfo> formInfos;
    int32_t userId = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_INFO_FAILED,
        formInfoHelper_->LoadFormConfigInfoByBundleName(FORM_BUNDLE_NAME_TEST, formInfos, userId));
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadFormConfigInfoByBundleName_0100 end";
}

/**
 * @tc.name: FormInfoHelper_LoadFormConfigInfoByBundleName_0200
 * @tc.number: LoadFormConfigInfoByBundleName
 * @tc.desc: call LoadFormConfigInfoByBundleName success
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_LoadFormConfigInfoByBundleName_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadFormConfigInfoByBundleName_0200 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "FormInfoHelper_LoadFormConfigInfoByBundleName_0200 bmsTask called";
        return true;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formInfoHelper_->LoadFormConfigInfoByBundleName(FORM_BUNDLE_NAME_TEST, formInfos, USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadFormConfigInfoByBundleName_0200 end";
}

/**
 * @tc.name: FormInfoHelper_LoadStageFormConfigInfo_0100
 * @tc.number: LoadStageFormConfigInfo
 * @tc.desc: call LoadStageFormConfigInfo with wrong extensionAbilityInfo type
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_LoadStageFormConfigInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadStageFormConfigInfo_0100 start";
    BundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.type = ExtensionAbilityType::WORK_SCHEDULER;
    bundleInfo.extensionInfos.push_back(extensionAbilityInfo);
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formInfoHelper_->LoadStageFormConfigInfo(bundleInfo, formInfos));
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadStageFormConfigInfo_0100 end";
}

/**
 * @tc.name: FormInfoHelper_LoadStageFormConfigInfo_0200
 * @tc.number: LoadStageFormConfigInfo
 * @tc.desc: call LoadStageFormConfigInfo with failed to get form metadata.
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_LoadStageFormConfigInfo_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadStageFormConfigInfo_0200 start";
    BundleInfo bundleInfo;
    ExtensionAbilityInfo extensionAbilityInfo;
    extensionAbilityInfo.type = ExtensionAbilityType::FORM;
    bundleInfo.extensionInfos.push_back(extensionAbilityInfo);
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formInfoHelper_->LoadStageFormConfigInfo(bundleInfo, formInfos));
    GTEST_LOG_(INFO) << "FormInfoHelper_LoadStageFormConfigInfo_0200 end";
}

/**
 * @tc.name: FormInfoHelper_GetResourceManager_0100
 * @tc.number: GetResourceManager
 * @tc.desc: call GetResourceManager with AddResource failed
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_GetResourceManager_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_GetResourceManager_0100 start";
    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.hapPath = "";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);
    EXPECT_NE(nullptr, formInfoHelper_->GetResourceManager(bundleInfo));
    GTEST_LOG_(INFO) << "FormInfoHelper_GetResourceManager_0100 end";
}

/**
 * @tc.name: FormInfoHelper_GetFormInfoDescription_0100
 * @tc.number: GetFormInfoDescription
 * @tc.desc: call GetFormInfoDescription with formInfo.descriptionId not 0
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_GetFormInfoDescription_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0100 start";
    BundleInfo bundleInfo;
    auto resourceManager = formInfoHelper_->GetResourceManager(bundleInfo);
    FormInfo formInfo;
    formInfo.descriptionId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, formInfoHelper_->GetFormInfoDescription(resourceManager, formInfo));
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0100 end";
}

/**
 * @tc.name: FormInfoHelper_GetFormInfoDescription_0200
 * @tc.number: GetFormInfoDescription
 * @tc.desc: call GetFormInfoDescription with GetStringById failed
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_GetFormInfoDescription_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0200 start";
    BundleInfo bundleInfo;
    auto resourceManager = formInfoHelper_->GetResourceManager(bundleInfo);
    FormInfo formInfo;
    formInfo.descriptionId = 0;
    EXPECT_EQ(ERR_OK, formInfoHelper_->GetFormInfoDescription(resourceManager, formInfo));
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0200 end";
}

/**
 * @tc.name: FormInfoHelper_GetFormInfoDescription_0300
 * @tc.number: GetFormInfoDescription
 * @tc.desc: call LoadFormConfigInfoByBundleName with GetStringById success
 */
HWTEST_F(FormInfoMgrTest, FormInfoHelper_GetFormInfoDescription_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0300 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0300 bmsTask called";
        return true;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK,
        formInfoHelper_->LoadFormConfigInfoByBundleName(FORM_BUNDLE_NAME_TEST, formInfos, USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormInfoHelper_GetFormInfoDescription_0300 end";
}

/**
 * @tc.name: BundleFormInfo_InitFromJson_0100
 * @tc.number: InitFromJson
 * @tc.desc: call InitFromJson with bad profile
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_InitFromJson_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_InitFromJson_0100 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::string formInfoStoragesJson = "";
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_BAD_PROFILE,
        bundleFormInfo.InitFromJson(formInfoStoragesJson));
    GTEST_LOG_(INFO) << "BundleFormInfo_InitFromJson_0100 end";
}

/**
 * @tc.name: BundleFormInfo_UpdateStaticFormInfos_0100
 * @tc.number: UpdateStaticFormInfos
 * @tc.desc: call UpdateStaticFormInfos with different form info
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_UpdateStaticFormInfos_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0100 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0100 bmsTask called";
        return true;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    FormInfo formInfo = GetTestFormInfo();
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(formInfo);
    formInfo.isStatic = false;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.UpdateStaticFormInfos(USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0100 end";
}

/**
 * @tc.name: BundleFormInfo_UpdateStaticFormInfos_0200
 * @tc.desc: test UpdateStaticFormInfos function and item->userId != userId.
 * @tc.type: FormInfoMgrTest
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_UpdateStaticFormInfos_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0200 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0200 bmsTask called";
        return true;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = 101;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.UpdateStaticFormInfos(USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "BundleFormInfo_UpdateStaticFormInfos_0200 end";
}

/**
 * @tc.name: BundleFormInfo_RemoveDynamicFormInfo_0100
 * @tc.number: RemoveDynamicFormInfo
 * @tc.desc: form info is not static, call RemoveDynamicFormInfo
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_RemoveDynamicFormInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_RemoveDynamicFormInfo_0100 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    FormInfo formInfo = GetTestFormInfo();
    formInfo.isStatic = false;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveDynamicFormInfo(PARAM_MODULE_NAME_TEST, PARAM_FORM_NAME, USER_ID));
    GTEST_LOG_(INFO) << "BundleFormInfo_RemoveDynamicFormInfo_0100 end";
}

/**
 * @tc.name: BundleFormInfo_RemoveAllDynamicFormsInfo_0100
 * @tc.number: RemoveAllDynamicFormsInfo
 * @tc.desc: form info is not static, call RemoveAllDynamicFormsInfo
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_RemoveAllDynamicFormsInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_RemoveAllDynamicFormsInfo_0100 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    FormInfo formInfo = GetTestFormInfo();
    formInfo.isStatic = false;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(formInfo);
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.RemoveAllDynamicFormsInfo(USER_ID));
    GTEST_LOG_(INFO) << "BundleFormInfo_RemoveAllDynamicFormsInfo_0100 end";
}

/**
 * @tc.name: BundleFormInfo_GetFormsInfoByModule_0100
 * @tc.number: GetFormsInfoByModule
 * @tc.desc: call GetFormsInfoByModule success
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_GetFormsInfoByModule_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByModule_0100 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::vector<FormInfo> formInfos;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    EXPECT_EQ(ERR_OK, bundleFormInfo.GetFormsInfoByModule(PARAM_MODULE_NAME_TEST, formInfos));
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByModule_0100 end";
}

/**
 * @tc.name: BundleFormInfo_GetFormsInfoByFilter_0100
 * @tc.number: GetFormsInfoByFilter
 * @tc.desc: call GetFormsInfoByFilter success
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_GetFormsInfoByFilter_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0100 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::vector<FormInfo> formInfos;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoFilter filter;
    filter.bundleName = FORM_BUNDLE_NAME_TEST;
    filter.moduleName = PARAM_MODULE_NAME_TEST;
    filter.supportDimensions = {1, 2};
    EXPECT_EQ(ERR_OK, bundleFormInfo.GetFormsInfoByFilter(filter, formInfos));
    EXPECT_EQ(1, formInfos.size());
    EXPECT_EQ(FORM_BUNDLE_NAME_TEST, formInfos[0].bundleName);
    EXPECT_EQ(PARAM_MODULE_NAME_TEST, formInfos[0].moduleName);
    EXPECT_EQ(filter.supportDimensions, formInfos[0].supportDimensions);
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0100 end";
}

/**
 * @tc.name: BundleFormInfo_GetFormsInfoByFilter_0200
 * @tc.number: GetFormsInfoByFilter
 * @tc.desc: call GetFormsInfoByFilter success
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_GetFormsInfoByFilter_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0200 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::vector<FormInfo> formInfos;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestCircleFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoFilter filter;
    filter.bundleName = FORM_BUNDLE_NAME_TEST;
    filter.moduleName = PARAM_MODULE_NAME_TEST;
    filter.supportShapes = {2};
    EXPECT_EQ(ERR_OK, bundleFormInfo.GetFormsInfoByFilter(filter, formInfos));
    EXPECT_EQ(1, formInfos.size());
    EXPECT_EQ(FORM_BUNDLE_NAME_TEST, formInfos[0].bundleName);
    EXPECT_EQ(PARAM_MODULE_NAME_TEST, formInfos[0].moduleName);
    EXPECT_EQ(filter.supportShapes, formInfos[0].supportShapes);
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0200 end";
}

/**
 * @tc.name: BundleFormInfo_GetFormsInfoByFilter_0200
 * @tc.number: GetFormsInfoByFilter
 * @tc.desc: call GetFormsInfoByFilter success
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_GetFormsInfoByFilter_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0300 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::vector<FormInfo> formInfos;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestCircleFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoFilter filter;
    filter.bundleName = FORM_BUNDLE_NAME_TEST;
    filter.moduleName = PARAM_MODULE_NAME_TEST;
    filter.supportDimensions = {1, 2};
    filter.supportShapes = {1};
    EXPECT_EQ(ERR_OK, bundleFormInfo.GetFormsInfoByFilter(filter, formInfos));
    EXPECT_EQ(0, formInfos.size());
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0300 end";
}

/**
 * @tc.name: BundleFormInfo_GetFormsInfoByFilter_0200
 * @tc.number: GetFormsInfoByFilter
 * @tc.desc: call GetFormsInfoByFilter success
 */
HWTEST_F(FormInfoMgrTest, BundleFormInfo_GetFormsInfoByFilter_0400, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0400 start";
    BundleFormInfo bundleFormInfo(FORM_BUNDLE_NAME_TEST);
    std::vector<FormInfo> formInfos;
    FormInfoStorage formInfoStorage;
    formInfoStorage.userId = USER_ID;
    formInfoStorage.formInfos.push_back(GetTestCircleFormInfo());
    bundleFormInfo.formInfoStorages_.emplace_back(formInfoStorage);
    FormInfoFilter filter;
    filter.bundleName = FORM_BUNDLE_NAME_TEST;
    filter.moduleName = PARAM_MODULE_NAME_TEST;
    filter.supportShapes = {2};
    filter.supportDimensions = {1, 2};
    EXPECT_EQ(ERR_OK, bundleFormInfo.GetFormsInfoByFilter(filter, formInfos));
    EXPECT_EQ(1, formInfos.size());
    EXPECT_EQ(FORM_BUNDLE_NAME_TEST, formInfos[0].bundleName);
    EXPECT_EQ(PARAM_MODULE_NAME_TEST, formInfos[0].moduleName);
    EXPECT_EQ(filter.supportShapes, formInfos[0].supportShapes);
    EXPECT_EQ(filter.supportDimensions, formInfos[0].supportDimensions);
    GTEST_LOG_(INFO) << "BundleFormInfo_GetFormsInfoByFilter_0400 end";
}

/**
 * @tc.name: FormInfoMgr_UpdateStaticFormInfos_0100
 * @tc.number: UpdateStaticFormInfos
 * @tc.desc: call UpdateStaticFormInfos success with update forms info
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_UpdateStaticFormInfos_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_UpdateStaticFormInfos_0100 start";
    sptr<MockBundleMgrProxy> bmsProxy = new (std::nothrow) MockBundleMgrProxy(new (std::nothrow) MockBundleMgrStub());
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bmsProxy;
    auto bmsTask = [] (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) {
        GTEST_LOG_(INFO) << "FormInfoMgr_UpdateStaticFormInfos_0100 bmsTask called";
        return true;
    };
    EXPECT_CALL(*bmsProxy, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));
    EXPECT_EQ(ERR_OK, formInfoMgr_.UpdateStaticFormInfos(FORM_BUNDLE_NAME_TEST, USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormInfoMgr_UpdateStaticFormInfos_0100 end";
}

/**
 * @tc.name: FormInfoMgr_Remove_0100
 * @tc.number: Remove
 * @tc.desc: call Remove success with and without BundleFormInfo
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_Remove_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_Remove_0100 start";
    EXPECT_EQ(ERR_OK, formInfoMgr_.Remove(FORM_BUNDLE_NAME_TEST, USER_ID));
    auto bundleFormInfo = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    bundleFormInfo->formInfoStorages_.clear();
    formInfoMgr_.bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfo;
    EXPECT_EQ(ERR_OK, formInfoMgr_.Remove(FORM_BUNDLE_NAME_TEST, USER_ID));
    EXPECT_EQ(ERR_OK, formInfoMgr_.Remove("bundleName", USER_ID));
    FormInfo formInfo = GetTestFormInfo();
    formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_Remove_0100 end";
}

/**
 * @tc.name: FormInfoMgr_GetFormsInfoByBundle_0100
 * @tc.number: GetFormsInfoByBundle
 * @tc.desc: call GetFormsInfoByBundle success
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_GetFormsInfoByBundle_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_GetFormsInfoByBundle_0100 start";
    auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    formInfoMgr_.bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfoPtr;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK, formInfoMgr_.GetFormsInfoByBundle(FORM_BUNDLE_NAME_TEST, formInfos));
    GTEST_LOG_(INFO) << "FormInfoMgr_GetFormsInfoByBundle_0100 end";
}

/**
 * @tc.name: FormInfoMgr_GetFormsInfoByModule_0100
 * @tc.number: GetFormsInfoByModule
 * @tc.desc: call GetFormsInfoByModule success
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_GetFormsInfoByModule_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_GetFormsInfoByModule_0100 start";
    auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    formInfoMgr_.bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfoPtr;
    std::vector<FormInfo> formInfos;
    EXPECT_EQ(ERR_OK,
        formInfoMgr_.GetFormsInfoByModule(FORM_BUNDLE_NAME_TEST, PARAM_MODULE_NAME_TEST, formInfos));
    GTEST_LOG_(INFO) << "FormInfoMgr_GetFormsInfoByModule_0100 end";
}

/**
 * @tc.name: FormInfoMgr_AddDynamicFormInfo_0100
 * @tc.number: AddDynamicFormInfo
 * @tc.desc: call AddDynamicFormInfo with wrong abilityName
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_AddDynamicFormInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_AddDynamicFormInfo_0100 start";
    EXPECT_EQ(ERR_OK, formInfoMgr_.Remove(FORM_BUNDLE_NAME_TEST, USER_ID));
    FormInfo formInfo = GetTestFormInfo();
    formInfo.abilityName = "ohos.samples.FormApplication";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_INFO_FAILED, formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID));

    sptr<MockBundleMgrStub> bms = new (std::nothrow) MockBundleMgrStub();
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bms;
    auto bmsTask = [] (const std::string &bundleName, int32_t flag, BundleInfo &bundleInfo, int32_t userId) {
        std::vector<AbilityInfo> abilityInfos;
        HapModuleInfo moduleInfo;
        AbilityInfo abilityInfo;
        moduleInfo.moduleName = PARAM_MODULE_NAME_TEST;
        abilityInfo.name = FORM_ABILITY_NAME_TEST;
        abilityInfo.package = FORM_BUNDLE_NAME_TEST;
        abilityInfo.bundleName = bundleName;
        abilityInfo.moduleName = PARAM_MODULE_NAME_TEST;
        moduleInfo.abilityInfos.push_back(abilityInfo);
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo);
        return true;
    };
    EXPECT_CALL(*bms, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));

    formInfo = GetTestFormInfo();
    EXPECT_EQ(ERR_OK, formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID));
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormInfoMgr_AddDynamicFormInfo_0100 end";
}

/**
 * @tc.name: FormInfoMgr_AddDynamicFormInfo_0200
 * @tc.number: AddDynamicFormInfo
 * @tc.desc: call AddDynamicFormInfo success with and without bundleFormInfo
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_AddDynamicFormInfo_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_AddDynamicFormInfo_0200 start";
    sptr<MockBundleMgrStub> bms = new (std::nothrow) MockBundleMgrStub();
    sptr<IBundleMgr> backup = FormBmsHelper::GetInstance().GetBundleMgr();
    FormBmsHelper::GetInstance().iBundleMgr_ = bms;
    auto bmsTask = [] (const std::string &bundleName, int32_t flag, BundleInfo &bundleInfo, int32_t userId) {
        std::vector<AbilityInfo> abilityInfos;
        HapModuleInfo moduleInfo;
        AbilityInfo abilityInfo;
        moduleInfo.moduleName = PARAM_MODULE_NAME_TEST;
        abilityInfo.name = FORM_ABILITY_NAME_TEST;
        abilityInfo.package = FORM_BUNDLE_NAME_TEST;
        abilityInfo.bundleName = bundleName;
        abilityInfo.moduleName = PARAM_MODULE_NAME_TEST;
        moduleInfo.abilityInfos.push_back(abilityInfo);
        bundleInfo.hapModuleInfos.emplace_back(moduleInfo);
        return true;
    };
    EXPECT_CALL(*bms, GetBundleInfo(_, _, _, _)).Times(1).WillOnce(Invoke(bmsTask));

    FormInfo formInfo = GetTestFormInfo();
    auto bundleFormInfoIter = formInfoMgr_.bundleFormInfoMap_.find(FORM_BUNDLE_NAME_TEST);
    if (bundleFormInfoIter == formInfoMgr_.bundleFormInfoMap_.end()) {
        EXPECT_EQ(ERR_OK, formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID));
    } else {
        formInfoMgr_.bundleFormInfoMap_.erase(bundleFormInfoIter);
        EXPECT_EQ(ERR_OK, formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID));
    }
    FormBmsHelper::GetInstance().iBundleMgr_ = backup;
    GTEST_LOG_(INFO) << "FormInfoMgr_AddDynamicFormInfo_0200 end";
}

/**
 * @tc.name: FormInfoMgr_RemoveDynamicFormInfo_0100
 * @tc.number: RemoveDynamicFormInfo
 * @tc.desc: call RemoveDynamicFormInfo but form is not dynamic
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_RemoveDynamicFormInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveDynamicFormInfo_0100 start";
    formInfoMgr_.Start();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formInfoMgr_.RemoveDynamicFormInfo(FORM_BUNDLE_NAME_TEST, PARAM_MODULE_NAME_TEST, PARAM_FORM_NAME, USER_ID));
    FormInfo formInfo = GetTestFormInfo();
    formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveDynamicFormInfo_0100 end";
}

/**
 * @tc.name: FormInfoMgr_RemoveAllDynamicFormsInfo_0100
 * @tc.number: RemoveAllDynamicFormsInfo
 * @tc.desc: call RemoveAllDynamicFormsInfo with no forms
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_RemoveAllDynamicFormsInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveAllDynamicFormsInfo_0100 start";
    formInfoMgr_.Start();
    auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(FORM_BUNDLE_NAME_TEST);
    formInfoMgr_.bundleFormInfoMap_[FORM_BUNDLE_NAME_TEST] = bundleFormInfoPtr;
    EXPECT_EQ(ERR_OK, formInfoMgr_.RemoveAllDynamicFormsInfo(FORM_BUNDLE_NAME_TEST, USER_ID));
    auto bundleFormInfoIter = formInfoMgr_.bundleFormInfoMap_.find(FORM_BUNDLE_NAME_TEST);
    if (bundleFormInfoIter == formInfoMgr_.bundleFormInfoMap_.end()) {
        EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
            formInfoMgr_.RemoveAllDynamicFormsInfo(FORM_BUNDLE_NAME_TEST, USER_ID));
    } else {
        formInfoMgr_.bundleFormInfoMap_.erase(bundleFormInfoIter);
        EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
            formInfoMgr_.RemoveAllDynamicFormsInfo(FORM_BUNDLE_NAME_TEST, USER_ID));
    }
    FormInfo formInfo = GetTestFormInfo();
    formInfoMgr_.AddDynamicFormInfo(formInfo, USER_ID);
    GTEST_LOG_(INFO) << "FormInfoMgr_RemoveAllDynamicFormsInfo_0100 end";
}

/**
 * @tc.name: FormInfoMgr_GetOrCreateBundleFromInfo_0100
 * @tc.number: GetOrCreateBundleFromInfo
 * @tc.desc: call GetOrCreateBundleFromInfo success null bundleFormInfo
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_GetOrCreateBundleFromInfo_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_GetOrCreateBundleFromInfo_0100 start";
    auto bundleFormInfoIter = formInfoMgr_.bundleFormInfoMap_.find(FORM_BUNDLE_NAME_TEST);
    if (bundleFormInfoIter == formInfoMgr_.bundleFormInfoMap_.end()) {
        EXPECT_NE(nullptr, formInfoMgr_.GetOrCreateBundleFromInfo(FORM_BUNDLE_NAME_TEST));
    } else {
        formInfoMgr_.bundleFormInfoMap_.erase(bundleFormInfoIter);
        EXPECT_NE(nullptr, formInfoMgr_.GetOrCreateBundleFromInfo(FORM_BUNDLE_NAME_TEST));
    }
    GTEST_LOG_(INFO) << "FormInfoMgr_GetOrCreateBundleFromInfo_0100 end";
}

/**
 * @tc.name: FormInfoMgr_IsCaller_0100
 * @tc.number: IsCaller
 * @tc.desc: call IsCaller with GetCallingTokenID failed
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_IsCaller_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_IsCaller_0100 start";
    formInfoMgr_.Start();
    EXPECT_FALSE(formInfoMgr_.IsCaller(FORM_BUNDLE_NAME_TEST));
    GTEST_LOG_(INFO) << "FormInfoMgr_IsCaller_0100 end";
}

/**
 * @tc.name: FormInfoMgr_ReloadFormInfos_0100
 * @tc.number: ReloadFormInfos
 * @tc.desc: call ReloadFormInfos success
 */
HWTEST_F(FormInfoMgrTest, FormInfoMgr_ReloadFormInfos_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_0100 start";
    formInfoMgr_.Start();
    EXPECT_EQ(ERR_OK, formInfoMgr_.ReloadFormInfos(USER_ID));
    GTEST_LOG_(INFO) << "FormInfoMgr_ReloadFormInfos_0100 end";
}