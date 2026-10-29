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

#include <cinttypes>
#include <cmath>
#include <limits>
#include <memory>
#include <string>

#include "form_instance.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "parcel.h"

#define private public
#include "js_form_host.h"
#include "napi_form_util.h"
#undef private

#include "js_form_agent.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace {
class FormAgentNapiTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_001
 * @tc.name: Verify UpdateFormCrossBundleCallbackInfo sentinel defaults.
 * @tc.desc: test the default-constructed callback info matches the parser's sentinel values.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_001 starts";
    UpdateFormCrossBundleCallbackInfo info;
    EXPECT_EQ(info.formId, -1);
    EXPECT_EQ(info.formBindingData, nullptr);
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_001 ends";
}

/**
 * @tc.number: FormAgentNapiTest_UpdateFormCrossBundle_004
 * @tc.name: Verify FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE value stability.
 * @tc.desc: test that the dedicated internal code 2293857 remains stable for the 201 mapping.
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_UpdateFormCrossBundle_004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_004 starts";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE, 2293857);

    EXPECT_EQ(ERR_FORM_EXTERNAL_PERMISSION_DENIED, 201);
    GTEST_LOG_(INFO) << "FormAgentNapiTest_UpdateFormCrossBundle_004 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_001
 * @tc.desc: Verify the formId parsing step rejects non-numeric strings and
 *           NOT_EXIST_ID (returned by GetVisibleFormRect for formId <= 0) resolves
 *           to external code 16501001 via the error table.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_001 starts";

    // ConvertFormId (js_form_agent.cpp) parses the JS formId string with
    // ConvertStringToInt64; a non-numeric string fails the parse and drives the
    // ThrowParamError rejection path.
    int64_t parsedFormId = -1;
    EXPECT_FALSE(ConvertStringToInt64("not-a-number", parsedFormId));
    EXPECT_FALSE(ConvertStringToInt64("12abc", parsedFormId));

    // GetVisibleFormRect returns NOT_EXIST_ID for formId <= 0; the reject path
    // maps it to the declared 16501001 (ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST).
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_NOT_EXIST_ID, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST);
    EXPECT_EQ(externalCode, 16501001);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_001 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_002
 * @tc.desc: Verify the wrong-argc rejection path throws with external code 401
 *           and INVALID_PARAM resolves to 401 via the error table.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_002 starts";

    // argc != 1 path: ThrowParamNumError / ThrowParamError throw with
    // ERR_FORM_EXTERNAL_PARAM_INVALID. Without a live env the guarded entry
    // returns false instead of throwing; the guard itself is observable SUT
    // behavior and must not crash.
    EXPECT_FALSE(NapiFormUtil::ThrowParamNumError(nullptr, "2", "1"));
    EXPECT_FALSE(NapiFormUtil::ThrowParamError(nullptr, "The formId is invalid."));

    // The code actually thrown on the argc path: the error table resolves
    // INVALID_PARAM to external 401 with the standard parameter-error message.
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_INVALID_PARAM, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_PARAM_INVALID);
    EXPECT_EQ(externalCode, 401);
    EXPECT_NE(message.find("Parameter error"), std::string::npos);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_002 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_003
 * @tc.desc: Verify the resolved Rect's four fields survive the parcel round-trip
 *           used to transport the host answer back to the agent.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_003 starts";

    // The host answer travels as a Parcelable Rect across the reverse IPC;
    // all four doubles must survive the marshalling round-trip.
    Rect rect;
    rect.left = 10.5;
    rect.top = 20.75;
    rect.width = 300.0;
    rect.height = 200.0;

    Parcel parcel;
    EXPECT_TRUE(rect.Marshalling(parcel));
    std::unique_ptr<Rect> read(Rect::Unmarshalling(parcel));
    ASSERT_NE(read, nullptr);
    EXPECT_DOUBLE_EQ(read->left, 10.5);
    EXPECT_DOUBLE_EQ(read->top, 20.75);
    EXPECT_DOUBLE_EQ(read->width, 300.0);
    EXPECT_DOUBLE_EQ(read->height, 200.0);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_003 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_004
 * @tc.desc: Verify GET_INFO_FAILED rejects with external code 16500100 through
 *           FormMgr::GetExternalError, the mapper behind the reject path.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_004 starts";

    // When no host listener settles the query, the Kit layer fails with
    // GET_INFO_FAILED and the promise reject path maps it via GetExternalError.
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_GET_INFO_FAILED, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_GET_INFO_FAILED);
    EXPECT_EQ(externalCode, 16500100);
    EXPECT_EQ(message, "Failed to obtain the configuration information.");

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_004 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_005
 * @tc.desc: Verify GET_SYSMGR_FAILED rejects with external code 16500050 and its
 *           dedicated detail message via the error table.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_005 starts";

    // SAMgr connection failures must land in the IPC bucket, distinct from the
    // GET_INFO_FAILED result bucket (see _004).
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_IPC_ERROR);
    EXPECT_EQ(externalCode, 16500050);
    EXPECT_EQ(message, "get system manager failed, or IPC connection error");
    EXPECT_NE(externalCode, ERR_FORM_EXTERNAL_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_005 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_006
 * @tc.desc: Verify non-contract internal codes converge to the TEMPLATE carrier
 *           via NormalizeIpcErrorCode and resolve to external code 16500050.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_006 starts";

    // The CompleteCallback converges the three non-contract transport codes
    // (proxy null / IPC send / parcel write failures) to the TEMPLATE carrier.
    EXPECT_EQ(NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_FORM_COMMON_CODE),
        ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED);
    EXPECT_EQ(NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_FORM_SEND_FMS_MSG),
        ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED);
    EXPECT_EQ(NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_PARCEL_ERROR),
        ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED);

    // The carrier itself resolves to the declared IPC external code.
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED, externalCode,
        message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_IPC_ERROR);
    EXPECT_EQ(externalCode, 16500050);
    EXPECT_EQ(message, "IPC connection error.");

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_006 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_Napi_007
 * @tc.desc: Verify SYSTEMCAP_ERROR resolves to external code 801 via the error
 *           table, the code the watch product guard rejects with.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_Napi_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_007 starts";

    // The NAPI layer does not gate on systemcap itself; the service watch
    // guard returns SYSTEMCAP_ERROR and the reject path maps it to 801.
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_SYSTEMCAP_ERROR, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR);
    EXPECT_EQ(externalCode, 801);
    EXPECT_NE(message.find("Capability not supported"), std::string::npos);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_Napi_007 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_HostNapi_001
 * @tc.desc: Verify the host on-path rejects a non-function callback with the
 *           exact 401 parameter-type error message.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_HostNapi_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_001 starts";

    // Host on-path: ThrowParamTypeError(env, "callback", "Callback<string>") rejects
    // non-function callbacks with 401; without a live env the guarded entry
    // returns false instead of throwing and must not crash.
    EXPECT_FALSE(NapiFormUtil::ThrowParamTypeError(nullptr, "callback", "Callback<string>"));

    // The exact rejection message the env-valid path throws.
    EXPECT_EQ(NapiFormUtil::CreateParamTypeErrorMessage("callback", "Callback<string>"),
        "Parameter error. The type of \"callback\" must be Callback<string>.");

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_001 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_HostNapi_002
 * @tc.desc: Verify the no-listener state is well-defined: the registry stays
 *           empty, off is a no-op success and a query settles as GET_INFO_FAILED.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_HostNapi_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_002 starts";

    auto mgr = JsFormRouterProxyMgr::GetInstance();
    ASSERT_TRUE(mgr != nullptr);

    // With no listener registered the registry reports empty ...
    EXPECT_FALSE(mgr->HasGetVisibleFormRectListener());

    // ... and a visibility query against the empty registry leaves the param
    // unsettled: result stays false and errCode keeps the GET_INFO_FAILED
    // sentinel, which is what the Kit layer turns into the 16500100 reject.
    auto param = std::make_shared<FormRectParam>();
    param->formId = "42";
    mgr->GetVisibleFormRectInner(param);
    EXPECT_FALSE(param->result);
    EXPECT_EQ(param->errCode, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);
    EXPECT_EQ(param->formId, "42");

    // off with an empty callback list is a no-op success and leaves the
    // no-registration state intact.
    EXPECT_TRUE(mgr->UnregisterGetVisibleFormRectListener());
    EXPECT_FALSE(mgr->HasGetVisibleFormRectListener());

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_002 ends";
}

/**
 * @tc.name: FormAgentNapiTest_GetVisibleFormRect_HostNapi_003
 * @tc.desc: Verify permission denials pass through the IPC remap and resolve to
 *           their own 201/202 codes instead of the 16500050 bucket.
 * @tc.type: FUNC
 */
HWTEST_F(FormAgentNapiTest, FormAgentNapiTest_GetVisibleFormRect_HostNapi_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_003 starts";

    // Permission denials keep their own codes through NormalizeIpcErrorCode
    // instead of being converged to the TEMPLATE carrier.
    int32_t passthrough = NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    EXPECT_EQ(passthrough, ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
    EXPECT_NE(passthrough, ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED);
    passthrough = NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    EXPECT_EQ(passthrough, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    passthrough = NapiFormUtil::NormalizeIpcErrorCode(ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);
    EXPECT_EQ(passthrough, ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);

    // The error table resolves the kept codes to their declared 201/202 codes,
    // distinct from the converged IPC bucket (16500050, see Napi_006).
    int32_t externalCode = 0;
    std::string message;
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
    EXPECT_EQ(externalCode, 202);
    FormMgr::GetInstance().GetExternalError(ERR_APPEXECFWK_FORM_PERMISSION_DENY, externalCode, message);
    EXPECT_EQ(externalCode, ERR_FORM_EXTERNAL_PERMISSION_DENIED);
    EXPECT_EQ(externalCode, 201);
    EXPECT_NE(externalCode, ERR_FORM_EXTERNAL_IPC_ERROR);

    GTEST_LOG_(INFO) << "FormAgentNapiTest_GetVisibleFormRect_HostNapi_003 ends";
}
}  // namespace
