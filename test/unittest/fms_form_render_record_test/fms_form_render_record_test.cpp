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

#include "form_constants.h"
#include "form_js_info.h"
#include "form_mgr_errors.h"
#define private public
#include "form_render_record.h"
#undef private
#include "gmock/gmock.h"
#include "fms_log_wrapper.h"
#include "js_runtime.h"
#include "mock_form_provider_client.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace {
    constexpr int32_t RELOAD_FORM_FAILED = -1;
}
class FormRenderRecordTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRenderRecordTest::SetUpTestCase()
{}

void FormRenderRecordTest::TearDownTestCase()
{}

void FormRenderRecordTest::SetUp()
{}

void FormRenderRecordTest::TearDown()
{}

/**
 * @tc.name: FormRenderRecordTest_001
 * @tc.desc: test HandleHostDied function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_001 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    int64_t formId = 1;
    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    formRenderRecord->hostsMapForFormId_.emplace(
        formId, std::unordered_set<sptr<IRemoteObject>, FormRenderRecord::RemoteObjHash>());
    EXPECT_EQ(true, formRenderRecord->HandleHostDied(hostRemoteObj));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_001 end";
}

/**
 * @tc.name: FormRenderRecordTest_002
 * @tc.desc: test CreateEventHandler function and eventHandler_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_002 start";
    std::string bundleName = "<bundleName>";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecord->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    EXPECT_EQ(true, formRenderRecord->CreateEventHandler(bundleName));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_002 end";
}

/**
 * @tc.name: FormRenderRecordTest_003
 * @tc.desc: test CreateEventHandler function and eventRunner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_003 start";
    std::string bundleName = "<bundleName>";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    formRenderRecord->eventRunner_ = EventRunner::Create(bundleName);
    formRenderRecord->eventHandler_ = nullptr;
    EXPECT_EQ(true, formRenderRecord->CreateEventHandler(bundleName));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_003 end";
}

/**
 * @tc.name: FormRenderRecordTest_004
 * @tc.desc: test DeleteRenderRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_004 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    ASSERT_NE(nullptr, formRenderRecord);
    int64_t formId = 1;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    formRenderRecord->DeleteRenderRecord(formId, compId, nullptr, isRenderGroupEmpty);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_004 end";
}

/**
 * @tc.name: FormRenderRecordTest_005
 * @tc.desc: test IsEmpty function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_005 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    EXPECT_EQ(true, formRenderRecord->IsEmpty());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_005 end";
}

/**
 * @tc.name: FormRenderRecordTest_006
 * @tc.desc: test GetUid function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_006 start";
    std::string uid = "uid";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    EXPECT_EQ(uid, formRenderRecord->GetUid());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_006 end";
}

/**
 * @tc.name: FormRenderRecordTest_007
 * @tc.desc: test CreateRuntime function and runtime_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_007 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    EXPECT_EQ(true, formRenderRecord->CreateRuntime(formJsInfo));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_007 end";
}

/**
 * @tc.name: FormRenderRecordTest_008
 * @tc.desc: test CreateRuntime function and runtime_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_008 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    // set runtime_ is not nullptr
    formRenderRecord->CreateRuntime(formJsInfo);
    // test CreateRuntime function
    EXPECT_EQ(true, formRenderRecord->CreateRuntime(formJsInfo));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_008 end";
}

/**
 * @tc.name: FormRenderRecordTest_009
 * @tc.desc: test CreateContext function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_009 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    Want want;
    EXPECT_NE(nullptr, formRenderRecord->CreateContext(formJsInfo, want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_009 end";
}

/**
 * @tc.name: FormRenderRecordTest_010
 * @tc.desc: test GetContext function and iter == contextsMapForModuleName_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_010 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    Want want;
    EXPECT_NE(nullptr, formRenderRecord->GetContext(formJsInfo, want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_010 end";
}

/**
 * @tc.name: FormRenderRecordTest_011
 * @tc.desc: test GetContext function and iter != contextsMapForModuleName_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_011 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    Want want;
    // set contextsMapForModuleName_
    formRenderRecord->CreateContext(formJsInfo, want);
    // test GetContext
    EXPECT_NE(nullptr, formRenderRecord->GetContext(formJsInfo, want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_011 end";
}

/**
 * @tc.name: FormRenderRecordTest_012
 * @tc.desc: test CreateFormRendererGroupLock function and formRendererGroup is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_012 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    EXPECT_NE(nullptr, formRenderRecord->CreateFormRendererGroupLock(formJsInfo, context, runtime));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_012 end";
}

/**
 * @tc.name: FormRenderRecordTest_013
 * @tc.desc: test GetFormRendererGroup function and iter == formRendererGroupMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_013 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    EXPECT_NE(nullptr, formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_013 end";
}

/**
 * @tc.name: FormRenderRecordTest_014
 * @tc.desc: test GetFormRendererGroup function and iter != formRendererGroupMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_014 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    // set formRendererGroupMap_
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    // test GetFormRendererGroup function
    EXPECT_NE(nullptr, formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_014 end";
}

/**
 * @tc.name: FormRenderRecordTest_015
 * @tc.desc: test HandleDeleteInJsThread function and search == formRendererGroupMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_015 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    int64_t formId = 1;
    std::string compId = "compId";
    EXPECT_EQ(false, formRenderRecord->HandleDeleteInJsThread(formId, compId));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_015 end";
}

/**
 * @tc.name: FormRenderRecordTest_016
 * @tc.desc: 1.test HandleDeleteInJsThread function and search != formRendererGroupMap_.end().
 *           2.search->second is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_016 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    int64_t formId = 1;
    std::string compId = "compId";
    formRenderRecord->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(false, formRenderRecord->HandleDeleteInJsThread(formId, compId));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_016 end";
}

/**
 * @tc.name: FormRenderRecordTest_017
 * @tc.desc: 1.test HandleDeleteInJsThread function and search != formRendererGroupMap_.end().
 *           2.search->second is not nullptr.
 *           3.compId is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_017 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    int64_t formId = 1;
    std::string compId = "compId";
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    EXPECT_EQ(false, formRenderRecord->HandleDeleteInJsThread(formId, compId));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_017 end";
}

/**
 * @tc.name: FormRenderRecordTest_018
 * @tc.desc: 1.test HandleDeleteInJsThread function and search != formRendererGroupMap_.end().
 *           2.search->second is not nullptr.
 *           3.compId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_018 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    int64_t formId = 1;
    std::string compId = "";
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    EXPECT_EQ(true, formRenderRecord->HandleDeleteInJsThread(formId, compId));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_018 end";
}

/**
 * @tc.name: FormRenderRecordTest_019
 * @tc.desc: test ReleaseHapFileHandle function and hapPath_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_019 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    ASSERT_NE(nullptr, formRenderRecord);
    formRenderRecord->hapPath_ = "";
    formRenderRecord->ReleaseHapFileHandle();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_019 end";
}

/**
 * @tc.name: FormRenderRecordTest_020
 * @tc.desc: test ReleaseHapFileHandle function and hapPath_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_020 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    ASSERT_NE(nullptr, formRenderRecord);
    formRenderRecord->hapPath_ = "hapPath";
    formRenderRecord->ReleaseHapFileHandle();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_020 end";
}

/**
 * @tc.name: FormRenderRecordTest_021
 * @tc.desc: test ReloadFormRecord function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_021 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderRecord->ReloadFormRecord(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_021 end";
}

/**
 * @tc.name: FormRenderRecordTest_022
 * @tc.desc: test HandleReloadFormRecord function and search == formRendererGroupMap_.end().
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_022 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    std::vector<FormJsInfo> formJsInfos;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    Want want;
    EXPECT_EQ(RELOAD_FORM_FAILED, formRenderRecord->HandleReloadFormRecord(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_022 end";
}

/**
 * @tc.name: FormRenderRecordTest_023
 * @tc.desc: 1.test HandleReloadFormRecord function and search != formRendererGroupMap_.end().
 *           2.group is nullptr;
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_023 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    std::vector<FormJsInfo> formJsInfos;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    Want want;
    formRenderRecord->formRendererGroupMap_.emplace(formJsInfo.formId, nullptr);
    EXPECT_EQ(RELOAD_FORM_FAILED, formRenderRecord->HandleReloadFormRecord(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_023 end";
}

/**
 * @tc.name: FormRenderRecordTest_024
 * @tc.desc: 1.test HandleReloadFormRecord function and search != formRendererGroupMap_.end().
 *           2.group is not nullptr;
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_024 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderRecord->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    EXPECT_EQ(ERR_OK, formRenderRecord->HandleReloadFormRecord(std::move(formJsInfos), want));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_024 end";
}

/**
 * @tc.name: FormRenderRecordTest_025
 * @tc.desc: 1.test HandleUpdateInJsThread function and runtime_ == nullptr.
 *           2.context != nullptr
 *           3.renderType != Constants::RENDER_FORM
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_025 start";
    auto formRenderRecord = FormRenderRecord::Create("bundleName", "uid");
    ASSERT_NE(nullptr, formRenderRecord);
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    // set formRendererGroupMap_
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecord->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderRecord->HandleUpdateInJsThread(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_025 end";
}