/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "form_supply_stub.h"
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
#include <thread>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;
using namespace OHOS::Ace;

namespace {
constexpr int32_t RELOAD_FORM_FAILED = -1;
constexpr int32_t RENDER_FORM_ID = -1;
constexpr int32_t RENDER_FORM_FAILED = -1;
constexpr int32_t RECYCLE_FORM_FAILED = -1;
constexpr int32_t SET_VISIBLE_CHANGE_FAILED = -1;
constexpr int32_t FORM_ID = 1;
}
#define private public
class FormRenderRecordMock : public FormRenderRecord {
public:
    static std::shared_ptr<FormRenderRecordMock> Create(const std::string &bundleName, const std::string &uid,
        bool needMonitored = true,  sptr<IFormSupply> formSupplyClient = nullptr)
    {
        std::shared_ptr<FormRenderRecordMock> renderRecord =
            std::make_shared<FormRenderRecordMock>(bundleName, uid, formSupplyClient);
        if (!renderRecord->CreateEventHandler(bundleName, needMonitored)) {
            return nullptr;
        }
        return renderRecord;
    }
    FormRenderRecordMock(const std::string &bundleName, const std::string &uid, sptr<IFormSupply> formSupplyClient)
        : FormRenderRecord(bundleName, uid, formSupplyClient) {}
    bool CreateRuntime(const FormJsInfo &formJsInfo)
    {
        return true;
    }
private:
    void HandleUpdateInJsThread(const FormJsInfo &formJsInfo, const Want &want){};
};
#undef private
class FormRenderRecordTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

static std::shared_ptr<FormRenderRecord> formRenderRecordPtr_ = nullptr;

void FormRenderRecordTest::SetUpTestCase()
{
    formRenderRecordPtr_ = FormRenderRecord::Create("bundleName", "uid");
}

void FormRenderRecordTest::TearDownTestCase()
{
    formRenderRecordPtr_ = nullptr;
}

void FormRenderRecordTest::SetUp()
{}

void FormRenderRecordTest::TearDown()
{}

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub() {};
    virtual ~MockFormSupplyStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return number_;
    };
    int HandleOnAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnEventHandle(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnAcquireStateResult(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int32_t HandleOnShareAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return number_;
    };
    int OnEventHandle(const Want &want) override
    {
        return number_;
    };
    int OnAcquireStateResult(FormState state, const std::string &pro, const Want &wantArg,
        const Want &want) override
    {
        return number_;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
    {
        return ERR_OK;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    const int number_ = 1;
};

/**
 * @tc.name: FormRenderRecordTest_001
 * @tc.desc: test HandleHostDied function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_001 start";

    int64_t formId = 1;
    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    formRenderRecordPtr_->hostsMapForFormId_.emplace(
        formId, std::unordered_set<sptr<IRemoteObject>, FormRenderRecord::RemoteObjHash>());
    EXPECT_EQ(true, formRenderRecordPtr_->HandleHostDied(hostRemoteObj));
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

    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    EXPECT_EQ(true, formRenderRecordPtr_->CreateEventHandler(bundleName));
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

    formRenderRecordPtr_->eventRunner_ = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = nullptr;
    EXPECT_EQ(true, formRenderRecordPtr_->CreateEventHandler(bundleName));
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

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    int64_t formId = 1;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    formRenderRecordPtr_->DeleteRenderRecord(formId, compId, nullptr, isRenderGroupEmpty);
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

    EXPECT_EQ(true, formRenderRecordPtr_->IsEmpty());
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

    EXPECT_EQ(uid, formRenderRecordPtr_->GetUid());
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

    FormJsInfo formJsInfo;
    formRenderRecordPtr_->eventRunner_ = nullptr;
    EXPECT_EQ(false, formRenderRecordPtr_->CreateRuntime(formJsInfo));
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

    FormJsInfo formJsInfo;
    formJsInfo.type = FormType::ETS;
    formJsInfo.uiSyntax = FormType::ETS;
    // set runtime_ is not nullptr
    formRenderRecordPtr_->eventRunner_ = EventRunner::Create("bundleName");
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    // test CreateRuntime function
    EXPECT_EQ(true, formRenderRecordPtr_->CreateRuntime(formJsInfo));
    formRenderRecordPtr_->runtime_ = nullptr;
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

    FormJsInfo formJsInfo;
    Want want;
    EXPECT_NE(nullptr, formRenderRecordPtr_->CreateContext(formJsInfo, want));
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

    FormJsInfo formJsInfo;
    Want want;
    EXPECT_NE(nullptr, formRenderRecordPtr_->GetContext(formJsInfo, want));
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

    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    Want want;
    // set contextsMapForModuleName_
    formRenderRecordPtr_->CreateContext(formJsInfo, want);
    // test GetContext
    EXPECT_NE(nullptr, formRenderRecordPtr_->GetContext(formJsInfo, want));
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

    FormJsInfo formJsInfo;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    EXPECT_NE(nullptr, formRenderRecordPtr_->CreateFormRendererGroupLock(formJsInfo, context, runtime));
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

    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    EXPECT_NE(nullptr, formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime));
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

    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    // set formRendererGroupMap_
    formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime);
    // test GetFormRendererGroup function
    EXPECT_NE(nullptr, formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime));
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

    int64_t formId = 1;
    std::string compId = "compId";
    EXPECT_EQ(false, formRenderRecordPtr_->HandleDeleteInJsThread(formId, compId));
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

    int64_t formId = 1;
    std::string compId = "compId";
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(false, formRenderRecordPtr_->HandleDeleteInJsThread(formId, compId));
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

    int64_t formId = 1;
    std::string compId = "compId";
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime);
    EXPECT_EQ(false, formRenderRecordPtr_->HandleDeleteInJsThread(formId, compId));
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

    int64_t formId = 1;
    std::string compId = "";
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime);
    EXPECT_EQ(true, formRenderRecordPtr_->HandleDeleteInJsThread(formId, compId));
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

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    formRenderRecordPtr_->hapPath_ = "";
    formRenderRecordPtr_->ReleaseHapFileHandle();
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

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    formRenderRecordPtr_->hapPath_ = "hapPath";
    formRenderRecordPtr_->ReleaseHapFileHandle();
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

    std::vector<FormJsInfo> formJsInfos;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderRecordPtr_->ReloadFormRecord(std::move(formJsInfos), want));
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

    std::vector<FormJsInfo> formJsInfos;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    Want want;
    formRenderRecordPtr_->formRendererGroupMap_.clear();
    formRenderRecordPtr_->runtime_ = nullptr;
    EXPECT_EQ(RELOAD_FORM_FAILED, formRenderRecordPtr_->HandleReloadFormRecord(std::move(formJsInfos), want));
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

    std::vector<FormJsInfo> formJsInfos;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    Want want;
    formRenderRecordPtr_->formRendererGroupMap_.clear();
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formJsInfo.formId, nullptr);
    EXPECT_EQ(RELOAD_FORM_FAILED, formRenderRecordPtr_->HandleReloadFormRecord(std::move(formJsInfos), want));
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

    std::vector<FormJsInfo> formJsInfos;
    Want want;
    // set formRendererGroupMap_
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    formJsInfos.emplace_back(formJsInfo);
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime);
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    EXPECT_EQ(ERR_OK, formRenderRecordPtr_->HandleReloadFormRecord(std::move(formJsInfos), want));
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

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    // set formRendererGroupMap_
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecordPtr_->GetFormRendererGroup(formJsInfo, context, runtime);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_025 end";
}

/**
 * @tc.name: FormRenderRecordTest_026
 * @tc.desc: Verify UpdateRenderRecord
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_026 start";

    FormJsInfo formJsInfo;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    formRenderRecordPtr_->hostsMapForFormId_.emplace(
        formId, std::unordered_set<sptr<IRemoteObject>, FormRenderRecord::RemoteObjHash>());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_026 end";
}

/**
 * @tc.name: FormRenderRecordTest_027
 * @tc.desc: Verify UpdateRenderRecord
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_027 start";

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    FormJsInfo formJsInfo;
    int64_t formId = 1;
    Want want;
    formRenderRecordPtr_->hostsMapForFormId_.emplace(
        formId, std::unordered_set<sptr<IRemoteObject>, FormRenderRecord::RemoteObjHash>());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_027 end";
}

/**
 * @tc.name: FormRenderRecordTest_028
 * @tc.desc: Verify HandleUpdateForm
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_028 start";

    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    formRenderRecordPtr_->HandleUpdateForm(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_028 end";
}

/**
 * @tc.name: FormRenderRecordTest_029
 * @tc.desc: Verify HandleUpdateForm
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_029 start";

    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    formRenderRecordPtr_->HandleUpdateForm(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_029 end";
}

/**
 * @tc.name: FormRenderRecordTest_030
 * @tc.desc: Verify CheckEventHandler
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_030 start";

    Want want;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->CheckEventHandler(true, true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_030 end";
}

/**
 * @tc.name: FormRenderRecordTest_031
 * @tc.desc: Verify CheckEventHandler
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_031 start";

    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    formRenderRecordPtr_->CheckEventHandler(true, true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_031 end";
}

/**
 * @tc.name: FormRenderRecordTest_032
 * @tc.desc: Verify AddFormRequest
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_032 start";
    FormJsInfo formJsInfo;
    Want want;

    formRenderRecordPtr_->AddFormRequest(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_032 end";
}

/**
 * @tc.name: FormRenderRecordTest_033
 * @tc.desc: Verify AddFormRequest
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_033 start";

    int64_t formId = 1;
    Ace::FormRequest formRequest;
    Want want;
    formRenderRecordPtr_->AddFormRequest(formId, formRequest);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_033 end";
}

/**
 * @tc.name: FormRenderRecordTest_034
 * @tc.desc: Verify UpdateFormRequestReleaseState
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_034 start";

    int64_t formId = 1;
    std::string compId = "compId";
    bool hasRelease = true;
    Want want;
    formRenderRecordPtr_->UpdateFormRequestReleaseState(formId, compId, hasRelease);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_034 end";
}

/**
 * @tc.name: FormRenderRecordTest_035
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_035 start";

    ASSERT_NE(nullptr, formRenderRecordPtr_);
    int64_t formId = 1;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    Want want;
    formRenderRecordPtr_->ReleaseRenderer(formId, compId, isRenderGroupEmpty);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_035 end";
}

/**
 * @tc.name: FormRenderRecordTest_036
 * @tc.desc: Verify HandleReleaseRendererInJsThread
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_036 start";

    int64_t formId = 1;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    Want want;
    formRenderRecordPtr_->hostsMapForFormId_.emplace(
        formId, std::unordered_set<sptr<IRemoteObject>, FormRenderRecord::RemoteObjHash>());

    EXPECT_EQ(false, formRenderRecordPtr_->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_036 end";
}

/**
 * @tc.name: FormRenderRecordTest_037
 * @tc.desc: Verify Release
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_037 start";

    formRenderRecordPtr_->Release();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_037 end";
}

/**
 * @tc.name: FormRenderRecordTest_038
 * @tc.desc: Verify ReAddAllRecycledForms
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_038 start";

    formRenderRecordPtr_->ReAddAllRecycledForms(nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_038 end";
}

/**
 * @tc.name: FormRenderRecordTest_039
 * @tc.desc: Verify HandleUpdateConfiguration
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_039 start";

    std::shared_ptr<OHOS::AppExecFwk::Configuration> config;
    formRenderRecordPtr_->HandleUpdateConfiguration(config);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_039 end";
}

/**
 * @tc.name: FormRenderRecordTest_040
 * @tc.desc: Verify IsMaxState
 * @tc.type: FUNC
 * @tc.require: IssueI99KFW
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_040 start";
    auto threadState = new FormRender::ThreadState(10);
    threadState->ResetState();
    threadState->NextState();
    int32_t state = threadState->GetCurrentState();
    EXPECT_EQ(1, state);
    bool isMaxState = threadState->IsMaxState();
    EXPECT_EQ(false, isMaxState);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_040 end";
}

/**
 * @tc.name: FormRenderRecordTest_041
 * @tc.desc: Verify handlerDumper
 * @tc.type: FUNC
 * @tc.require: IssueI99KFW
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_041 start";
    auto handlerDumper = new FormRender::HandlerDumper();
    handlerDumper->Dump("FormRenderRecordTest_041");
    EXPECT_EQ("FormRenderRecordTest_041", handlerDumper->GetDumpInfo());
    EXPECT_EQ("", handlerDumper->GetTag());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_041 end";
}

/**
 * @tc.name: FormRenderRecordTest_042
 * @tc.desc: Verify DumpEventHandler
 * @tc.type: FUNC
 * @tc.require: IssueI99KFW
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_042 start";
    std::string bundleName = "<bundleName>";

    EXPECT_EQ(true, formRenderRecordPtr_->CreateEventHandler(bundleName));
    formRenderRecordPtr_->DumpEventHandler();
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    EXPECT_EQ(true, formRenderRecordPtr_->CreateEventHandler(bundleName));
    formRenderRecordPtr_->DumpEventHandler();
    formRenderRecordPtr_->DeleteRendererGroup(RENDER_FORM_ID);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_042 end";
}

/**
 * @tc.name: FormRenderRecordTest_043
 * @tc.desc: Verify BeforeHandleUpdateForm
 * @tc.type: FUNC
 * @tc.require: IssueI99KFW
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_043 start";
    std::string bundleName = "<bundleName>";

    std::shared_ptr<OHOS::AppExecFwk::Configuration> config;
    formRenderRecordPtr_->SetConfiguration(config);
    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    Want want;
    formRenderRecordPtr_->eventRunner_ = nullptr;
    formRenderRecordPtr_->HandleUpdateInJsThread(formJsInfo, want);
    EXPECT_EQ(false, formRenderRecordPtr_->BeforeHandleUpdateForm(formJsInfo));
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    EXPECT_EQ(true, formRenderRecordPtr_->BeforeHandleUpdateForm(formJsInfo));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_043 end";
}

/**
 * @tc.name: FormRenderRecordTest_044
 * @tc.desc: Verify AddRenderer
 * @tc.type: FUNC
 * @tc.require: IssueI99KFW
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_044 start";

    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    Want want;
    formRenderRecordPtr_->AddRenderer(formJsInfo, want);
    formRenderRecordPtr_->eventHandler_ = nullptr;
    GTEST_LOG_(INFO) << "FormRenderRecordTest_044 end";
}

/**
 * @tc.name: FormRenderRecordTest_045
 * @tc.desc: Verify SetPkgContextInfoMap
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_045 start";

    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    AbilityRuntime::Runtime::Options options;
    EXPECT_EQ(true, formRenderRecordPtr_->SetPkgContextInfoMap(formJsInfo, options));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_045 end";
}

/**
 * @tc.name: FormRenderRecordTest_046
 * @tc.desc: Verify RecoverFormsByConfigUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_046 start";

    std::vector<int64_t> formIds;
    formRenderRecordPtr_->RecoverFormsByConfigUpdate(formIds, nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_046 end";
}

/**
 * @tc.name: FormRenderRecordTest_047
 * @tc.desc: Test DeleteRendererGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_047 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    formRenderRecordPtr_->formRendererGroupMap_.emplace(55, nullptr);
    int64_t formId = 64;
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));
    formRenderRecordPtr_->DeleteRendererGroup(formId);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_047 end";
}

/**
 * @tc.name: FormRenderRecordTest_048
 * @tc.desc: Test DeleteRendererGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_048 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    int64_t formId = 64101;
    formRenderRecordPtr_->DeleteRendererGroup(formId);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_048 end";
}

/**
 * @tc.name: FormRenderRecordTest_049
 * @tc.desc: Test UpdateRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_049 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    FormJsInfo info;
    info.isDynamic = false;
    Want want;
    EXPECT_EQ(formRenderRecordPtr_->UpdateRenderRecord(info, want, nullptr), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_049 end";
}

/**
 * @tc.name: FormRenderRecordTest_050
 * @tc.desc: Test UpdateRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_050 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    FormJsInfo info;
    info.isDynamic = false;
    Want want;
    EXPECT_EQ(formRenderRecordPtr_->UpdateRenderRecord(info, want, nullptr), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_050 end";
}

/**
 * @tc.name: FormRenderRecordTest_051
 * @tc.desc: Test UpdateRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_051 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    FormJsInfo info;
    info.isDynamic = false;
    info.formId = 15;
    Want want;

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    formRenderRecordPtr_->formSupplyClient_ = formSupplyClient;

    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(formRenderRecordPtr_->UpdateRenderRecord(info, want, hostRemoteObj), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_051 end";
}

/**
 * @tc.name: FormRenderRecordTest_052
 * @tc.desc: Test UpdateRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_052 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    FormJsInfo info;
    info.isDynamic = false;
    info.formId = 15;
    Want want;

    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(formRenderRecordPtr_->UpdateRenderRecord(info, want, hostRemoteObj), ERR_OK);
    sptr<IRemoteObject> hostRemoteObjOther = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(formRenderRecordPtr_->UpdateRenderRecord(info, want, hostRemoteObjOther), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_052 end";
}

/**
 * @tc.name: FormRenderRecordTest_053
 * @tc.desc: Test HandleDeleteRendererGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_053, TestSize.Level0)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    GTEST_LOG_(INFO) << "FormRenderRecordTest_053 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 64;
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));

    formRenderRecordPtr_->HandleDeleteRendererGroup(formId);
    EXPECT_EQ(0, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_053 end";
}

/**
 * @tc.name: FormRenderRecordTest_054
 * @tc.desc: Test HandleDeleteRendererGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_054, TestSize.Level0)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    GTEST_LOG_(INFO) << "FormRenderRecordTest_054 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 64;
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));

    formRenderRecordPtr_->HandleDeleteRendererGroup(formId + 10);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRendererGroupMap_.size()));
    formRenderRecordPtr_->formRendererGroupMap_.clear();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_054 end";
}

/**
 * @tc.name: FormRenderRecordTest_055
 * @tc.desc: Test MergeFormData
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_055, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_055 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    FormRequest request;
    request.formJsInfo.formData = "test";
    FormJsInfo info;

    formRenderRecordPtr_->MergeFormData(request, info);
    EXPECT_EQ("", request.formJsInfo.formData);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_055 end";
}

/**
 * @tc.name: FormRenderRecordTest_056
 * @tc.desc: Test RunTask
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_056, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_056 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    EXPECT_EQ(TaskState::NO_RUNNING, formRenderRecordPtr_->RunTask());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_056 end";
}

/**
 * @tc.name: FormRenderRecordTest_057
 * @tc.desc: Test RunTask
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_057, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_057 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    formRenderRecordPtr_->CheckEventHandler(true, false);
    formRenderRecordPtr_->threadState_ = std::make_unique<ThreadState>(2);
    EXPECT_EQ(TaskState::RUNNING, formRenderRecordPtr_->RunTask());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_057 end";
}

/**
 * @tc.name: FormRenderRecordTest_058
 * @tc.desc: Test RunTask
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_058, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_058 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    formRenderRecordPtr_->CheckEventHandler(true, false);
    formRenderRecordPtr_->threadState_ = std::make_unique<ThreadState>(1);
    formRenderRecordPtr_->threadIsAlive_ = false;

    EXPECT_EQ(TaskState::BLOCK, formRenderRecordPtr_->RunTask());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_058 end";
}

/**
 * @tc.name: FormRenderRecordTest_059
 * @tc.desc: Test DeleteFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_059 start";
    EXPECT_TRUE(formRenderRecordPtr_);

    formRenderRecordPtr_->formRequests_.clear();
    int64_t formId = 15;
    FormRequest request;
    std::unordered_map<std::string, Ace::FormRequest> map;
    map.emplace("1", request);

    formRenderRecordPtr_->formRequests_.emplace(formId, map);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));
    formRenderRecordPtr_->DeleteFormRequest(formId, "1");
    EXPECT_EQ(0, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_059 end";
}

/**
 * @tc.name: FormRenderRecordTest_060
 * @tc.desc: Test DeleteFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_060 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRequests_.clear();

    int64_t formId = 15;
    FormRequest request;
    std::unordered_map<std::string, Ace::FormRequest> map;
    map.emplace("1", request);
    formRenderRecordPtr_->formRequests_.emplace(formId, map);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));

    formRenderRecordPtr_->DeleteFormRequest(formId, "test");
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));

    formRenderRecordPtr_->formRequests_.clear();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_060 end";
}

/**
 * @tc.name: FormRenderRecordTest_061
 * @tc.desc: Test HandleRecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_061, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_061 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    std::string statusData("test");
    EXPECT_EQ(RECYCLE_FORM_FAILED, formRenderRecordPtr_->HandleRecycleForm(formId, statusData));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_061 end";
}

/**
 * @tc.name: FormRenderRecordTest_062
 * @tc.desc: Test HandleRecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_062, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_062 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    std::string statusData("test");
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(RECYCLE_FORM_FAILED, formRenderRecordPtr_->HandleRecycleForm(formId, statusData));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_062 end";
}

/**
 * @tc.name: FormRenderRecordTest_063
 * @tc.desc: Test HandleRecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_063, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_063 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    std::string statusData("test");
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    EXPECT_EQ(ERR_OK, formRenderRecordPtr_->HandleRecycleForm(formId, statusData));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_063 end";
}

/**
 * @tc.name: FormRenderRecordTest_064
 * @tc.desc: Verify RecoverFormRequestsInGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_064, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_064 start";

    FormJsInfo formJsInfo;
    std::string statusData = "";
    bool isHandleClickEvent = false;
    std::unordered_map<std::string, Ace::FormRequest> requests;
    bool ret = formRenderRecordPtr_->RecoverFormRequestsInGroup(formJsInfo, statusData, isHandleClickEvent, requests);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_064 end";
}

/**
 * @tc.name: FormRenderRecordTest_065
 * @tc.desc: Verify RecoverRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_065, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_065 start";

    std::vector<Ace::FormRequest> requests;
    size_t requestIndex = 0;
    bool ret = formRenderRecordPtr_->RecoverRenderer(requests, requestIndex);
    EXPECT_EQ(false, ret);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_065 end";
}

/**
 * @tc.name: FormRenderRecordTest_066
 * @tc.desc: Verify MarkThreadAlive
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_066, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_066 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->threadState_ = std::make_unique<ThreadState>(1);
    ASSERT_NE(formRenderRecordPtr_->threadState_, nullptr);
    formRenderRecordPtr_->MarkThreadAlive();
    EXPECT_EQ(formRenderRecordPtr_->threadState_->state_, 0);
    EXPECT_EQ(formRenderRecordPtr_->threadIsAlive_, true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_066 end";
}

/**
 * @tc.name: FormRenderRecordTest_067
 * @tc.desc: Verify UpdateRuntime
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_067 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    formRenderRecordPtr_->contextsMapForModuleName_.emplace(formJsInfo.bundleName + ":" + formJsInfo.moduleName,
        nullptr);
    bool result = formRenderRecordPtr_->UpdateRuntime(formJsInfo);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_067 end";
}

/**
 * @tc.name: FormRenderRecordTest_068
 * @tc.desc: Verify UpdateRuntime
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_068, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_068 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    FormJsInfo formJsInfo;
    formRenderRecordPtr_->runtime_ = nullptr;
    bool result = formRenderRecordPtr_->UpdateRuntime(formJsInfo);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_068 end";
}

/**
 * @tc.name: FormRenderRecordTest_069
 * @tc.desc: Verify UpdateRuntime
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_069, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_069 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    FormJsInfo formJsInfo;
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    ASSERT_NE(formRenderRecordPtr_->runtime_, nullptr);
    formRenderRecordPtr_->contextsMapForModuleName_.clear();
    bool result = formRenderRecordPtr_->UpdateRuntime(formJsInfo);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_069 end";
}

/**
 * @tc.name: FormRenderRecordTest_070
 * @tc.desc: Verify GetContext
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_070, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_070 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    FormJsInfo formJsInfo;
    Want want;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    formRenderRecordPtr_->contextsMapForModuleName_.clear();
    formRenderRecordPtr_->contextsMapForModuleName_.emplace(formJsInfo.bundleName + ":" + formJsInfo.moduleName,
        nullptr);
    auto result = formRenderRecordPtr_->GetContext(formJsInfo, want);
    EXPECT_EQ(result, nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_070 end";
}

/**
 * @tc.name: FormRenderRecordTest_071
 * @tc.desc: Verify AddFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_071, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_071 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRequests_.clear();

    int64_t formId = FORM_ID;
    Ace::FormRequest formRequest;
    formRequest.compId = "compId";
    std::unordered_map<std::string, Ace::FormRequest> requests;
    requests.emplace(formRequest.compId, formRequest);
    formRenderRecordPtr_->formRequests_.emplace(formId, requests);
    formRequest.hasRelease = true;
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.find(formId)->second.find(formRequest.compId)->second.hasRelease,
        false);
    formRenderRecordPtr_->AddFormRequest(formId, formRequest);
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.find(formId)->second.find(formRequest.compId)->second.hasRelease,
        true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_071 end";
}

/**
 * @tc.name: FormRenderRecordTest_072
 * @tc.desc: Verify UpdateFormRequestReleaseState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_072, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_072 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRequests_.clear();

    int64_t formId = FORM_ID;
    std::string compId = "compId";
    bool hasRelease = true;
    std::unordered_map<std::string, Ace::FormRequest> requests;
    formRenderRecordPtr_->formRequests_.emplace(formId, requests);
    formRenderRecordPtr_->UpdateFormRequestReleaseState(formId, compId, hasRelease);
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.find(formId)->second.find(compId),
              formRenderRecordPtr_->formRequests_.find(formId)->second.end());
    GTEST_LOG_(INFO) << "FormRenderRecordTest_072 end";
}

/**
 * @tc.name: FormRenderRecordTest_073
 * @tc.desc: Verify UpdateFormRequestReleaseState
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_073, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_073 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRequests_.clear();

    Ace::FormRequest formRequest;
    int64_t formId = FORM_ID;
    std::string compId = "compId";
    bool hasRelease = true;
    std::unordered_map<std::string, Ace::FormRequest> requests;
    requests.emplace(compId, formRequest);
    formRenderRecordPtr_->formRequests_.emplace(formId, requests);
    formRenderRecordPtr_->UpdateFormRequestReleaseState(formId, compId, hasRelease);
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.find(formId)->second.find(compId)->second.hasRelease, true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_073 end";
}

/**
 * @tc.name: FormRenderRecordTest_074
 * @tc.desc: Verify HandleReleaseRendererInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_074, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_074 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::string compId = "";
    bool isRenderGroupEmpty = true;
    EXPECT_EQ(false, formRenderRecordPtr_->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_074 end";
}

/**
 * @tc.name: FormRenderRecordTest_075
 * @tc.desc: Verify HandleReleaseRendererInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_075, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_075 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    EXPECT_EQ(false, formRenderRecordPtr_->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_075 end";
}

/**
 * @tc.name: FormRenderRecordTest_076
 * @tc.desc: Verify HandleReleaseRendererInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_076, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_076 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(false, formRenderRecordPtr_->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_076 end";
}

/**
 * @tc.name: FormRenderRecordTest_077
 * @tc.desc: Verify HandleReleaseRendererInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_077, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_077 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = FORM_ID;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    ASSERT_NE(group, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    EXPECT_EQ(true, formRenderRecordPtr_->HandleReleaseRendererInJsThread(formId, compId, isRenderGroupEmpty));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_077 end";
}

/**
 * @tc.name: FormRenderRecordTest_078
 * @tc.desc: Verify HandleDestroyInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_078, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_078 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    ASSERT_NE(group, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    formRenderRecordPtr_->HandleDestroyInJsThread();
    EXPECT_EQ(formRenderRecordPtr_->formRendererGroupMap_.empty(), true);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_078 end";
}

/**
 * @tc.name: FormRenderRecordTest_079
 * @tc.desc: Verify UpdateConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_079, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_079 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->UpdateConfiguration(nullptr, nullptr);
    EXPECT_EQ(formRenderRecordPtr_->configuration_, nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_079 end";
}

/**
 * @tc.name: FormRenderRecordTest_080
 * @tc.desc: Verify OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_080, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_080 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->eventHandler_ = nullptr;
    EXPECT_EQ(formRenderRecordPtr_->OnUnlock(), RENDER_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_080 end";
}

/**
 * @tc.name: FormRenderRecordTest_081
 * @tc.desc: Verify OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_081, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_081 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    EXPECT_EQ(formRenderRecordPtr_->OnUnlock(), ERR_OK);
    formRenderRecordPtr_->eventHandler_ = nullptr;
    GTEST_LOG_(INFO) << "FormRenderRecordTest_081 end";
}

/**
 * @tc.name: FormRenderRecordTest_082
 * @tc.desc: Verify HandleOnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_082, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_082 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    ASSERT_NE(group, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    EXPECT_EQ(formRenderRecordPtr_->HandleOnUnlock(), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_082 end";
}

/**
 * @tc.name: FormRenderRecordTest_083
 * @tc.desc: Verify FormCount
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_083, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_083 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    EXPECT_EQ(formRenderRecordPtr_->FormCount(), 0);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_083 end";
}

/**
 * @tc.name: FormRenderRecordTest_084
 * @tc.desc: Verify UpdateConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_084, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_084 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> config = std::make_shared<Configuration>();
    ASSERT_NE(config, nullptr);
    formRenderRecordPtr_->UpdateConfiguration(config, nullptr);
    EXPECT_NE(formRenderRecordPtr_->configuration_, nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_084 end";
}

/**
 * @tc.name: FormRenderRecordTest_085
 * @tc.desc: Verify RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_085, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_085 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = FORM_ID;
    std::string statusData;
    EXPECT_EQ(formRenderRecordPtr_->RecycleForm(formId, statusData), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_085 end";
}

/**
 * @tc.name: FormRenderRecordTest_086
 * @tc.desc: Verify RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_086, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_086 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = FORM_ID;
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    std::string statusData;
    EXPECT_EQ(formRenderRecordPtr_->RecycleForm(formId, statusData), RECYCLE_FORM_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_086 end";
}

/**
 * @tc.name: FormRenderRecordTest_087
 * @tc.desc: Verify RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_087, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_087 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = FORM_ID;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    ASSERT_NE(group, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    std::string statusData;
    EXPECT_EQ(formRenderRecordPtr_->RecycleForm(formId, statusData), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_087 end";
}

/**
 * @tc.name: FormRenderRecordTest_088
 * @tc.desc: Verify RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_088, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_088 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    FormJsInfo formJsInfo;
    std::string statusData;
    EXPECT_EQ(formRenderRecordPtr_->RecoverForm(formJsInfo, statusData, true), ERR_OK);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_088 end";
}

/**
 * @tc.name: FormRenderRecordTest_089
 * @tc.desc: Verify RecoverRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_089, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_089 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    Ace::FormRequest formRequest;
    std::vector<Ace::FormRequest> requests;
    requests.emplace_back(formRequest);
    size_t requestIndex = 0;
    bool ret = formRenderRecordPtr_->RecoverRenderer(requests, requestIndex);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_089 end";
}

/**
 * @tc.name: FormRenderRecordTest_090
 * @tc.desc: Verify RecoverRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_090, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_090 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    FormJsInfo formJsInfo;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    Ace::FormRequest formRequest;
    formRequest.formJsInfo = formJsInfo;
    std::vector<Ace::FormRequest> requests;
    requests.emplace_back(formRequest);
    size_t requestIndex = 0;
    formRenderRecordPtr_->contextsMapForModuleName_.emplace(formJsInfo.bundleName + ":" + formJsInfo.moduleName,
        nullptr);
    formRenderRecordPtr_->RecoverRenderer(requests, requestIndex);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_090 end";
}

/**
 * @tc.name: FormRenderRecordTest_091
 * @tc.desc: Test HandleSetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_091, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_091 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    EXPECT_EQ(SET_VISIBLE_CHANGE_FAILED, formRenderRecordPtr_->HandleSetVisibleChange(formId, true));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_091 end";
}

/**
 * @tc.name: FormRenderRecordTest_092
 * @tc.desc: Test HandleSetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_092, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_092 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(SET_VISIBLE_CHANGE_FAILED, formRenderRecordPtr_->HandleSetVisibleChange(formId, true));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_092 end";
}

/**
 * @tc.name: FormRenderRecordTest_093
 * @tc.desc: Test HandleSetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_093, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_093 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRendererGroupMap_.clear();

    int64_t formId = 15;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> handler = nullptr;
    auto group = std::make_shared<FormRendererGroup>(context, runtime, handler);
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, group);
    EXPECT_EQ(ERR_OK, formRenderRecordPtr_->HandleSetVisibleChange(formId, true));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_093 end";
}

/**
 * @tc.name: FormRenderRecordTest_094
 * @tc.desc: Verify SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_094, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_094 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    EXPECT_EQ(formRenderRecordPtr_->SetVisibleChange(formId, true), SET_VISIBLE_CHANGE_FAILED);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_094 end";
}

/**
 * @tc.name: FormRenderRecordTest_095
 * @tc.desc: Verify SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_095, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_095 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    int64_t formId = FORM_ID;
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    EXPECT_EQ(formRenderRecordPtr_->SetVisibleChange(formId, true), ERR_OK);
    formRenderRecordPtr_->eventHandler_ = nullptr;
    GTEST_LOG_(INFO) << "FormRenderRecordTest_095 end";
}


/**
 * @tc.name: FormRenderRecordTest_096
 * @tc.desc: Verify OnRenderingBlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_096, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_096 start";
    formRenderRecordPtr_->OnRenderingBlock("123");
    GTEST_LOG_(INFO) << "FormRenderRecordTest_096 end";
}

/**
 * @tc.name: FormRenderRecordTest_097
 * @tc.desc: Verify OnNotifyRefreshForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_097, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_097 start";
    formRenderRecordPtr_->OnNotifyRefreshForm(123);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_097 end";
}

/**
 * @tc.name: FormRenderRecordTest_098
 * @tc.desc: Verify Timer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_098, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_098 start";
    formRenderRecordPtr_->threadIsAlive_ = false;
    formRenderRecordPtr_->threadState_ = std::make_unique<ThreadState>(0);
    formRenderRecordPtr_->Timer();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_098 end";
}

/**
 * @tc.name: FormRenderRecordTest_099
 * @tc.desc: Verify RunTask
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_099, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_099 start";
    formRenderRecordPtr_->eventHandler_ = nullptr;
    EXPECT_EQ(formRenderRecordPtr_->RunTask(), TaskState::NO_RUNNING);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_099 end";
}

/**
 * @tc.name: FormRenderRecordTest_100
 * @tc.desc: Verify DumpEventHandler
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_100 start";
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->DumpEventHandler();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_100 end";
}

/**
 * @tc.name: FormRenderRecordTest_102
 * @tc.desc: Verify UpdateRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_102 start";
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    FormJsInfo info;
    info.isDynamic = false;
    Want want;
    formRenderRecordPtr_->UpdateRenderRecord(info, want, nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_102 end";
}

/**
 * @tc.name: FormRenderRecordTest_103
 * @tc.desc: Verify DeleteRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_103 start";
    formRenderRecordPtr_->eventHandler_ = nullptr;
    bool isRenderGroupEmpty = true;
    formRenderRecordPtr_->DeleteRenderRecord(123, "123", nullptr, isRenderGroupEmpty);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_103 end";
}

/**
 * @tc.name: FormRenderRecordTest_104
 * @tc.desc: Verify DeleteRenderRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_104 start";
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    sptr<IRemoteObject> hostRemoteObj = new (std::nothrow) MockFormProviderClient();
    bool isRenderGroupEmpty = true;
    formRenderRecordPtr_->DeleteRenderRecord(123, "123", hostRemoteObj, isRenderGroupEmpty);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_104 end";
}

/**
 * @tc.name: FormRenderRecordTest_106
 * @tc.desc: Verify UpdateRuntime
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_106 start";
    formRenderRecordPtr_->runtime_ = nullptr;
    FormJsInfo info;
    formRenderRecordPtr_->UpdateRuntime(info);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_106 end";
}

/**
 * @tc.name: FormRenderRecordTest_107
 * @tc.desc: Verify UpdateRuntime
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_107, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_107 start";
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    FormJsInfo info;
    info.formName = "123";
    info.moduleName = "456";
    info.isDynamic = false;
    info.abilityName = "789";
    formRenderRecordPtr_->UpdateRuntime(info);
    formRenderRecordPtr_->runtime_ = nullptr;
    GTEST_LOG_(INFO) << "FormRenderRecordTest_107 end";
}

/**
 * @tc.name: FormRenderRecordTest_108
 * @tc.desc: Verify SetPkgContextInfoMap
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_108, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_108 start";
    FormJsInfo info;
    std::map<std::string, std::string> modulePkgNameMap;
    modulePkgNameMap.insert(std::pair<std::string, std::string>("pkg_name", "pkg_name"));
    modulePkgNameMap.insert(std::pair<std::string, std::string>("hap_path", "hap_path"));
    info.modulePkgNameMap = modulePkgNameMap;
    AbilityRuntime::Runtime::Options options;
    formRenderRecordPtr_->SetPkgContextInfoMap(info, options);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_108 end";
}

/**
 * @tc.name: FormRenderRecordTest_109
 * @tc.desc: Verify SetPkgContextInfoMap
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_109, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_109 start";
    FormJsInfo info;
    std::map<std::string, std::string> modulePkgNameMap;
    modulePkgNameMap.insert(std::pair<std::string, std::string>("123", "123"));
    modulePkgNameMap.insert(std::pair<std::string, std::string>("456", "456"));
    info.modulePkgNameMap = modulePkgNameMap;
    AbilityRuntime::Runtime::Options options;
    formRenderRecordPtr_->SetPkgContextInfoMap(info, options);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_109 end";
}

/**
 * @tc.name: FormRenderRecordTest_110
 * @tc.desc: Verify SetConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_110, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_110 start";
    std::shared_ptr<OHOS::AppExecFwk::Configuration> config = std::make_shared<Configuration>();
    config->AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE, "0");
    config->AddItem(OHOS::AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE, "1.7");
    formRenderRecordPtr_->configuration_ = config;
    formRenderRecordPtr_->SetConfiguration(config);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_110 end";
}

/**
 * @tc.name: FormRenderRecordTest_111
 * @tc.desc: Verify GetContext
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_111, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_111 start";
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam("form_compatible_version", 1);
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    formRenderRecordPtr_->contextsMapForModuleName_.clear();
    formRenderRecordPtr_->contextsMapForModuleName_.emplace(formJsInfo.bundleName + ":" + formJsInfo.moduleName,
        nullptr);
    auto result = formRenderRecordPtr_->GetContext(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_111 end";
}

/**
 * @tc.name: FormRenderRecordTest_112
 * @tc.desc: Verify CreateFormRendererGroupLock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_112, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_112 start";
    FormJsInfo formJsInfo;
    std::shared_ptr<AbilityRuntime::Context> context = nullptr;
    std::shared_ptr<AbilityRuntime::Runtime> runtime = nullptr;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->CreateFormRendererGroupLock(formJsInfo, context, runtime);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_112 end";
}

/**
 * @tc.name: FormRenderRecordTest_113
 * @tc.desc: Verify HandleUpdateForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_113, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_113 start";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    formRenderRecordPtr_->HandleUpdateForm(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_113 end";
}

/**
 * @tc.name: FormRenderRecordTest_114
 * @tc.desc: Verify AddRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_114, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_114 start";
    FormJsInfo formJsInfo;
    Want want;
    want.SetParam(Constants::FORM_COMPATIBLE_VERSION_KEY, 1);
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    formRenderRecordPtr_->contextsMapForModuleName_.clear();
    formRenderRecordPtr_->contextsMapForModuleName_.emplace(formJsInfo.bundleName + ":" + formJsInfo.moduleName,
        nullptr);
    formRenderRecordPtr_->AddRenderer(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_114 end";
}

/**
 * @tc.name: FormRenderRecordTest_115
 * @tc.desc: Verify UpdateRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_115, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_114 start";
    int64_t formId = 1;
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    formJsInfo.bundleName = "bundleName";
    formJsInfo.moduleName = "moduleName";
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    formRenderRecordPtr_->UpdateRenderer(formJsInfo);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_115 end";
}

/**
 * @tc.name: FormRenderRecordTest_116
 * @tc.desc: Verify UpdateRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_116, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_116 start";
    FormJsInfo formJsInfo;
    formRenderRecordPtr_->UpdateRenderer(formJsInfo);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_116 end";
}

/**
 * @tc.name: FormRenderRecordTest_117
 * @tc.desc: Verify HandleDeleteInJsThread
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_117, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_117 start";
    int64_t formId = 123;
    std::string compId = "compId";
    formRenderRecordPtr_->formRendererGroupMap_.clear();
    formRenderRecordPtr_->formRendererGroupMap_.emplace(formId, nullptr);
    EXPECT_EQ(false, formRenderRecordPtr_->HandleDeleteInJsThread(formId, compId));
    GTEST_LOG_(INFO) << "FormRenderRecordTest_117 end";
}

/**
 * @tc.name: FormRenderRecordTest_118
 * @tc.desc: Verify AddFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_118, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_118 start";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Want want;
    want.SetParam(OHOS::AppExecFwk::Constants::FORM_RENDER_COMP_ID, 1);
    formRenderRecordPtr_->AddFormRequest(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_118 end";
}

/**
 * @tc.name: FormRenderRecordTest_119
 * @tc.desc: Verify UpdateFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_119, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_119 start";

    ASSERT_NE(formRenderRecordPtr_, nullptr);
    formRenderRecordPtr_->formRequests_.clear();

    int64_t formId = FORM_ID;
    Ace::FormRequest formRequest;
    formRequest.compId = "compId";
    std::unordered_map<std::string, Ace::FormRequest> requests;
    requests.emplace(formRequest.compId, formRequest);
    formRenderRecordPtr_->formRequests_.emplace(formId, requests);
    formRequest.hasRelease = true;

    Want want;
    want.SetParam(OHOS::AppExecFwk::Constants::FORM_RENDER_COMP_ID, "1");
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, UPDATE_RENDERING_FORM);
    FormJsInfo formJsInfo;
    formJsInfo.formId = formId;
    formRenderRecordPtr_->UpdateFormRequest(formJsInfo, want);
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.empty(), true);

    want.RemoveParam(Constants::FORM_RENDER_TYPE_KEY);
    EXPECT_EQ(formRenderRecordPtr_->formRequests_.find(formId) != formRenderRecordPtr_->formRequests_.end(), true);

    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, UPDATE_RENDERING_FORM);
    formRenderRecordPtr_->UpdateFormRequest(formJsInfo, want);
    formJsInfo.formData = "{\"aaa\":\"bbb\"}";
    auto formRequest = formRenderRecordPtr_->formRequests_.find(formId);
    EXPECT_EQ(formRequest != formRenderRecordPtr_->formRequests_.end(), true);
    EXPECT_EQ(formRequest.second.formJsInfo.formData, formJsInfo.formData);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_119 end";
}

/**
 * @tc.name: FormRenderRecordTest_120
 * @tc.desc: Test DeleteFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_120, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_120 start";

    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRequests_.clear();
    int64_t formId = 15;
    FormRequest request;
    std::unordered_map<std::string, Ace::FormRequest> map;
    map.emplace("1", request);
    formRenderRecordPtr_->formRequests_.emplace(formId, map);
    EXPECT_EQ(1, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));
    formRenderRecordPtr_->DeleteFormRequest(formId, "");
    EXPECT_EQ(0, static_cast<int>(formRenderRecordPtr_->formRequests_.size()));
    formRenderRecordPtr_->formRequests_.clear();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_120 end";
}

/**
 * @tc.name: FormRenderRecordTest_121
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_121, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_121 start";
    ASSERT_NE(nullptr, formRenderRecordPtr_);
    int64_t formId = 1;
    std::string compId = "compId";
    bool isRenderGroupEmpty = true;
    Want want;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->ReleaseRenderer(formId, compId, isRenderGroupEmpty);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_121 end";
}

/**
 * @tc.name: FormRenderRecordTest_122
 * @tc.desc: Verify RecoverFormsByConfigUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_122, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_122 start";
    std::vector<int64_t> formIds;
    sptr<IFormSupply> formSupplyClient;
    formRenderRecordPtr_->RecoverFormsByConfigUpdate(formIds, formSupplyClient);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_122 end";
}

/**
 * @tc.name: FormRenderRecordTest_123
 * @tc.desc: Verify RecoverFormsByConfigUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_123, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_123 start";
    std::vector<int64_t> formIds;
    sptr<IFormSupply> formSupplyClient;
    formRenderRecordPtr_->RecoverFormsByConfigUpdate(formIds, formSupplyClient);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_123 end";
}

/**
 * @tc.name: FormRenderRecordTest_124
 * @tc.desc: Verify ReAddAllRecycledForms
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_124, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_124 start";
    sptr<IFormSupply> formSupplyClient;
    formRenderRecordPtr_->ReAddAllRecycledForms(formSupplyClient);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_124 end";
}

/**
 * @tc.name: FormRenderRecordTest_125
 * @tc.desc: Verify ReAddAllRecycledForms
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_125, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_125 start";
    sptr<IFormSupply> formSupplyClient;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->ReAddAllRecycledForms(formSupplyClient);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_125 end";
}

/**
 * @tc.name: FormRenderRecordTest_126
 * @tc.desc: Verify ReAddRecycledForms
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_126, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_126 start";
    FormJsInfo formJsInfo1;
    FormJsInfo formJsInfo2;
    FormJsInfo formJsInfo3;
    std::vector<FormJsInfo> formJsInfos = {formJsInfo1, formJsInfo2, formJsInfo3};
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    formRenderRecordPtr_->ReAddRecycledForms(formJsInfos);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_126 end";
}

/**
 * @tc.name: FormRenderRecordTest_127
 * @tc.desc: Verify ReloadFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_127, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_127 start";
    std::vector<FormJsInfo> formJsInfos;
    Want want;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->ReloadFormRecord(std::move(formJsInfos), want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_127 end";
}

/**
 * @tc.name: FormRenderRecordTest_129
 * @tc.desc: Verify ReloadFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_129, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_129 start";
    std::vector<FormJsInfo> formJsInfos;
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    formRenderRecordPtr_->ReAddIfHapPathChanged(formJsInfos);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_129 end";
}

/**
 * @tc.name: FormRenderRecordTest_130
 * @tc.desc: Verify ReAddIfHapPathChanged
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_130, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_130 start";
    std::vector<FormJsInfo> formJsInfos;
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->ReAddIfHapPathChanged(formJsInfos);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_130 end";
}

/**
 * @tc.name: FormRenderRecordTest_131
 * @tc.desc: Verify UpdateAllFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_131, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_131 start";
    bool hasRelease = true;
    FormJsInfo formJsInfo1;
    FormJsInfo formJsInfo2;
    FormJsInfo formJsInfo3;
    std::vector<FormJsInfo> formJsInfos = {formJsInfo1, formJsInfo2, formJsInfo3};
    formRenderRecordPtr_->UpdateAllFormRequest(formJsInfos, hasRelease);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_131 end";
}

/**
 * @tc.name: FormRenderRecordTest_132
 * @tc.desc: Verify OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_132, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_132 start";
    std::string bundleName = "<bundleName>";
    auto eventRunner = EventRunner::Create(bundleName);
    formRenderRecordPtr_->eventHandler_ = std::make_shared<EventHandler>(eventRunner);
    formRenderRecordPtr_->OnUnlock();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_132 end";
}

/**
 * @tc.name: FormRenderRecordTest_133
 * @tc.desc: Verify HandleReloadFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_133, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_133 start";
    std::vector<FormJsInfo> formJsInfos;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 123;
    formJsInfos.emplace_back(formJsInfo);
    Want want;
    formRenderRecordPtr_->formRendererGroupMap_.clear();
    formRenderRecordPtr_->formRendererGroupMap_.emplace(456, nullptr);
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    formRenderRecordPtr_->HandleReloadFormRecord(std::move(formJsInfos), want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_133 end";
}

/**
 * @tc.name: FormRenderRecordTest_134
 * @tc.desc: Verify HandleUpdateConfiguration
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_134, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_134 start";
    formRenderRecordPtr_->formRendererGroupMap_.emplace(456, nullptr);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> config;
    formRenderRecordPtr_->HandleUpdateConfiguration(config);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_134 end";
}

/**
 * @tc.name: FormRenderRecordTest_136
 * @tc.desc: Verify FormRenderGC
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_136, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_136 start";
    formRenderRecordPtr_->eventHandler_ = nullptr;
    formRenderRecordPtr_->FormRenderGC();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_136 end";
}

/**
 * @tc.name: FormRenderRecordTest_137
 * @tc.desc: Verify RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_137, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_137 start";
    formRenderRecordPtr_->eventHandler_ = nullptr;
    int64_t formId = 123;
    std::string statusData;
    formRenderRecordPtr_->RecycleForm(formId, statusData);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_137 end";
}

/**
 * @tc.name: FormRenderRecordTest_138
 * @tc.desc: Verify HandleRecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_138, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_138 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRequests_.clear();
    Ace::FormRequest formRequest;
    std::unordered_map<std::string, Ace::FormRequest> formRequests = {{"345", formRequest}};
    FormJsInfo formJsInfo;
    formJsInfo.formId = 345;
    formRenderRecordPtr_->formRequests_.emplace(345, formRequests);
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    formRenderRecordPtr_->HandleRecoverForm(formJsInfo, statusData, isHandleClickEvent);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_138 end";
}

/**
 * @tc.name: FormRenderRecordTest_139
 * @tc.desc: Verify HandleRecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_139, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_139 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->formRequests_.clear();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 345;
    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    formRenderRecordPtr_->formRequests_.emplace(345, formRequests);
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    formRenderRecordPtr_->HandleRecoverForm(formJsInfo, statusData, isHandleClickEvent);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_139 end";
}

/**
 * @tc.name: FormRenderRecordTest_140
 * @tc.desc: Verify GetAndDeleteRecycledCompIds
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_140, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_140 start";
    int64_t formId = 123;
    std::vector<std::string> orderedCompIds = {"123", "456", "789"};
    std::string currentCompId = "456";
    formRenderRecordPtr_->recycledFormCompIds_.clear();
    std::pair<std::vector<std::string>, std::string> pp;
    formRenderRecordPtr_->recycledFormCompIds_.emplace(formId, pp);
    formRenderRecordPtr_->GetAndDeleteRecycledCompIds(formId, orderedCompIds, currentCompId);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_140 end";
}

/**
 * @tc.name: FormRenderRecordTest_141
 * @tc.desc: Verify RecoverFormRequestsInGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_141, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_141 start";
    int64_t formId = 123;
    formRenderRecordPtr_->recycledFormCompIds_.clear();
    std::pair<std::vector<std::string>, std::string> pp;
    formRenderRecordPtr_->recycledFormCompIds_.emplace(formId, pp);
    FormJsInfo formJsInfo;
    formJsInfo.formId = 123;
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    std::unordered_map<std::string, Ace::FormRequest> recordFormRequests;
    formRenderRecordPtr_->RecoverFormRequestsInGroup(formJsInfo, statusData, isHandleClickEvent, recordFormRequests);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_141 end";
}

/**
 * @tc.name: FormRenderRecordTest_142
 * @tc.desc: Verify RecoverFormRequestsInGroup
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_142, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_142 start";
    int64_t formId = 123;
    formRenderRecordPtr_->recycledFormCompIds_.clear();
    std::pair<std::vector<std::string>, std::string> pp;
    formRenderRecordPtr_->recycledFormCompIds_.emplace(formId, pp);
    std::unordered_map<std::string, Ace::FormRequest> formRequests;
    formRenderRecordPtr_->formRequests_.emplace(123, formRequests);
    FormJsInfo formJsInfo;
    formJsInfo.formId = 123;
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    std::unordered_map<std::string, Ace::FormRequest> recordFormRequests;
    formRenderRecordPtr_->RecoverFormRequestsInGroup(formJsInfo, statusData, isHandleClickEvent, recordFormRequests);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_142 end";
}

/**
 * @tc.name: FormRenderRecordTest_143
 * @tc.desc: Verify UpdateGroupRequestsWhenRecover
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_143, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_143 start";
    int64_t formId = 123;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 123;
    std::vector<std::string> orderedCompIds = {"123", "456", "789"};
    std::string currentCompId = "123";
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    size_t currentRequestIndex;
    Ace::FormRequest formRequest1;
    std::vector<Ace::FormRequest> groupRequests;
    bool currentRequestFound = true;
    std::unordered_map<std::string, Ace::FormRequest> recordFormRequests {{"456", formRequest1}};
    formRenderRecordPtr_->UpdateGroupRequestsWhenRecover(formId, formJsInfo, orderedCompIds, currentCompId,
        statusData, isHandleClickEvent, currentRequestIndex, groupRequests, currentRequestFound,
        recordFormRequests);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_143 end";
}

/**
 * @tc.name: FormRenderRecordTest_144
 * @tc.desc: Verify UpdateGroupRequestsWhenRecover
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_144, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_144 start";
    int64_t formId = 123;
    FormJsInfo formJsInfo;
    formJsInfo.formId = 123;
    std::vector<std::string> orderedCompIds = {"123", "456", "789"};
    std::string currentCompId = "456";
    std::string statusData = "123";
    bool isHandleClickEvent = true;
    size_t currentRequestIndex;
    Ace::FormRequest formRequest1;
    std::string compId;
    OHOS::AAFwk::Want want;
    formRequest1.compId = "123";
    formRequest1.want = want;
    Ace::FormRequest formRequest2;
    Ace::FormRequest formRequest3;
    std::vector<Ace::FormRequest> groupRequests;
    bool currentRequestFound = true;
    std::unordered_map<std::string, Ace::FormRequest> recordFormRequests {{"123", formRequest1}, {"456", formRequest2}};
    recordFormRequests.insert({"567", formRequest3});
    formRenderRecordPtr_->UpdateGroupRequestsWhenRecover(formId, formJsInfo, orderedCompIds, currentCompId,
        statusData, isHandleClickEvent, currentRequestIndex, groupRequests, currentRequestFound,
        recordFormRequests);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_144 end";
}

/**
 * @tc.name: FormRenderRecordTest_145
 * @tc.desc: Verify MergeMap
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_145, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_145 start";
    sptr<FormAshmem> formAshmem1;
    sptr<FormAshmem> formAshmem2;
    sptr<FormAshmem> formAshmem3;
    sptr<FormAshmem> formAshmem4;
    sptr<FormAshmem> formAshmem5;
    std::map<std::string, sptr<FormAshmem>> dst;
    dst.insert({"123", formAshmem1});
    dst.insert({"456", formAshmem2});
    dst.insert({"789", formAshmem4});
    std::map<std::string, sptr<FormAshmem>> src;
    src.insert({"123", formAshmem1});
    src.insert({"345", formAshmem3});
    src.insert({"789", formAshmem5});
    formRenderRecordPtr_->MergeMap(dst, src);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_145 end";
}

/**
 * @tc.name: FormRenderRecordTest_146
 * @tc.desc: Verify UpdateFormSizeOfGroups
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_146, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_146 start";
    int64_t formId = 123;
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    formRenderRecordPtr_->UpdateFormSizeOfGroups(formId, width, height, borderWidth);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_146 end";
}

/**
 * @tc.name: FormRenderRecordTest_147
 * @tc.desc: Verify UpdateFormSizeOfGroups
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_147, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_147 start";

    EXPECT_TRUE(formRenderRecordPtr_);

    formRenderRecordPtr_->formRequests_.clear();
    int64_t formId = 123;
    FormRequest request;
    std::unordered_map<std::string, Ace::FormRequest> map;
    map.emplace("123", request);
    formRenderRecordPtr_->formRequests_.emplace(formId, map);
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    formRenderRecordPtr_->UpdateFormSizeOfGroups(formId, width, height, borderWidth);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_147 end";
}

/**
 * @tc.name: FormRenderRecordTest_148
 * @tc.desc: Verify UpdateFormSizeOfGroups
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_148, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_148 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->HasRenderFormTask();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_148 end";
}

/**
 * @tc.name: FormRenderRecordTest_149
 * @tc.desc: Verify AddFormRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_149, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_149 start";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    std::string value = "1";
    Want want;
    want.SetParam(OHOS::AppExecFwk::Constants::FORM_RENDER_COMP_ID, value);
    formRenderRecordPtr_->AddFormRequest(formJsInfo, want);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_149 end";
}

/**
 * @tc.name: FormRenderRecordTest_150
 * @tc.desc: Verify RegisterUncatchableErrorHandler
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_150, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_150 start";
    EXPECT_TRUE(formRenderRecordPtr_);
    formRenderRecordPtr_->runtime_ = std::make_shared<AbilityRuntime::JsRuntime>();
    formRenderRecordPtr_->RegisterUncatchableErrorHandler();
    GTEST_LOG_(INFO) << "FormRenderRecordTest_150 end";
}

/**
 * @tc.name: FormRenderRecordTest_151
 * @tc.desc: Verify GetNativeStrFromJsTaggedObj
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_151, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_151 start";
    std::string result = formRenderRecordPtr_->GetNativeStrFromJsTaggedObj(nullptr, "testKey");
    EXPECT_EQ(result, "");
    GTEST_LOG_(INFO) << "FormRenderRecordTest_151 end";
}

/**
 * @tc.name: FormRenderRecordTest_152
 * @tc.desc: Verify OnJsError
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderRecordTest, FormRenderRecordTest_152, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderRecordTest_152 start";
    formRenderRecordPtr_->OnJsError(nullptr);
    GTEST_LOG_(INFO) << "FormRenderRecordTest_152 end";
}