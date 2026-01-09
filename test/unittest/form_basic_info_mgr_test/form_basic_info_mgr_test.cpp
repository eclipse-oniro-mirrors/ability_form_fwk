/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#define private public
#include "data_center/form_basic_info_mgr.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
int64_t TEST_FORM_ID = 12345;
const std::string BUNDLE_NAME = "com.example.test";
const std::string FORM_NAME = "TestForm";
const std::string ABILITY_NAME = "com.huawei.hmos.notepad";
const std::string MODULE_NAME = "TestModule";
const std::string PACKAGE_NAME = "TestPackage";
const std::string INVALID_VALUE = "";
const FormBasicInfo BASIC_INFO{TEST_FORM_ID, ABILITY_NAME, BUNDLE_NAME, MODULE_NAME, FORM_NAME, PACKAGE_NAME};

class FormBasicInfoMgrTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormBasicInfoMgr &formBasicInfoMgr = FormBasicInfoMgr::GetInstance();
};

void FormBasicInfoMgrTest::SetUp()
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
}

void FormBasicInfoMgrTest::TearDown()
{
    formBasicInfoMgr.ClearFormBasicInfo();
}

/**
 * @tc.name: FormBasicInfoMgr_001
 * @tc.desc: test GetFormBasicInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_001, TestSize.Level1)
{
    const auto formSize = formBasicInfoMgr.GetBasicInfoCount();
    EXPECT_EQ(formSize, 1);
}

/**
 * @tc.name: FormBasicInfoMgr_002
 * @tc.desc: test get expect value function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_002, TestSize.Level1)
{
    const auto abilityName = formBasicInfoMgr.GetFormAbilityName(TEST_FORM_ID);
    const auto bundleName = formBasicInfoMgr.GetFormBundleName(TEST_FORM_ID);
    const auto moduleName = formBasicInfoMgr.GetFormModuleName(TEST_FORM_ID);
    const auto formName = formBasicInfoMgr.GetFormName(TEST_FORM_ID);
    const auto packageName = formBasicInfoMgr.GetFormPackageName(TEST_FORM_ID);
    EXPECT_EQ(abilityName, ABILITY_NAME);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    EXPECT_EQ(moduleName, MODULE_NAME);
    EXPECT_EQ(formName, FORM_NAME);
    EXPECT_EQ(packageName, PACKAGE_NAME);
}

/**
 * @tc.name: FormBasicInfoMgr_003
 * @tc.desc: test get null value with wrong form id function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_003, TestSize.Level1)
{
    int64_t formId = 1;
    const std::string abilityName = formBasicInfoMgr.GetFormAbilityName(formId);
    const std::string bundleName = formBasicInfoMgr.GetFormBundleName(formId);
    const std::string moudleName = formBasicInfoMgr.GetFormModuleName(formId);
    const std::string formName = formBasicInfoMgr.GetFormName(formId);
    const std::string packageName = formBasicInfoMgr.GetFormPackageName(formId);
    EXPECT_EQ(abilityName, INVALID_VALUE);
    EXPECT_EQ(bundleName, INVALID_VALUE);
    EXPECT_EQ(moudleName, INVALID_VALUE);
    EXPECT_EQ(formName, INVALID_VALUE);
    EXPECT_EQ(packageName, INVALID_VALUE);
}

/**
 * @tc.name: FormBasicInfoMgr_004
 * @tc.desc: test delete basic info function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_004, TestSize.Level1)
{
    const auto formSize = formBasicInfoMgr.GetBasicInfoCount();
    EXPECT_EQ(formSize, 1);
    formBasicInfoMgr.DeleteFormBasicInfo(TEST_FORM_ID);
    const auto formSizeDeleted = formBasicInfoMgr.GetBasicInfoCount();
    EXPECT_EQ(formSizeDeleted, 0);
}

/**
 * @tc.name: FormBasicInfoMgr_005
 * @tc.desc: test update basic info abilityName function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_005, TestSize.Level1)
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
    const auto abilityName = formBasicInfoMgr.GetFormAbilityName(TEST_FORM_ID);
    EXPECT_EQ(abilityName, ABILITY_NAME);
    const std::string newAbilityName = "newAbilityName";
    formBasicInfoMgr.UpdateAbilityName(TEST_FORM_ID, newAbilityName);
    const auto updatedName = formBasicInfoMgr.GetFormAbilityName(TEST_FORM_ID);
    EXPECT_NE(updatedName, abilityName);
}

/**
 * @tc.name: FormBasicInfoMgr_006
 * @tc.desc: test update basic info moduleName function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_006, TestSize.Level1)
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
    const auto moduleName = formBasicInfoMgr.GetFormModuleName(TEST_FORM_ID);
    EXPECT_EQ(moduleName, MODULE_NAME);
    const std::string newModuleName = "newModuleName";
    formBasicInfoMgr.UpdateModuleName(TEST_FORM_ID, newModuleName);
    const auto updatedName = formBasicInfoMgr.GetFormModuleName(TEST_FORM_ID);
    EXPECT_NE(updatedName, moduleName);
}

/**
 * @tc.name: FormBasicInfoMgr_007
 * @tc.desc: test update basic info bundleName function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_007, TestSize.Level1)
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
    const auto bundleName = formBasicInfoMgr.GetFormBundleName(TEST_FORM_ID);
    EXPECT_EQ(bundleName, BUNDLE_NAME);
    const std::string newBundleName = "newBundleName";
    formBasicInfoMgr.UpdateBundleName(TEST_FORM_ID, newBundleName);
    const auto updatedName = formBasicInfoMgr.GetFormBundleName(TEST_FORM_ID);
    EXPECT_NE(updatedName, bundleName);
}

/**
 * @tc.name: FormBasicInfoMgr_008
 * @tc.desc: test update basic info formName function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_008, TestSize.Level1)
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
    const auto formName = formBasicInfoMgr.GetFormName(TEST_FORM_ID);
    EXPECT_EQ(formName, FORM_NAME);
    const std::string newFormName = "newFormName";
    formBasicInfoMgr.UpdateFormName(TEST_FORM_ID, newFormName);
    const auto updatedName = formBasicInfoMgr.GetFormName(TEST_FORM_ID);
    EXPECT_NE(updatedName, formName);
}

/**
 * @tc.name: FormBasicInfoMgr_009
 * @tc.desc: test update basic info formName function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBasicInfoMgrTest, FormBasicInfoMgr_009, TestSize.Level1)
{
    formBasicInfoMgr.AddFormBasicInfo(BASIC_INFO);
    const auto packageName = formBasicInfoMgr.GetFormPackageName(TEST_FORM_ID);
    EXPECT_EQ(packageName, PACKAGE_NAME);
    const std::string newPackageName = "newPackageName";
    formBasicInfoMgr.UpdatePackageName(TEST_FORM_ID, newPackageName);
    const auto updatedName = formBasicInfoMgr.GetFormPackageName(TEST_FORM_ID);
    EXPECT_NE(updatedName, packageName);
}
}  // namespace