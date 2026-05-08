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
#include "form_want.h"
#include "want.h"
#include "want_params.h"
#include "form_constants.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {

using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

class FmsFormWantTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void FmsFormWantTest::SetUpTestCase(void)
{
}

void FmsFormWantTest::TearDownTestCase(void)
{
}

void FmsFormWantTest::SetUp()
{
}

void FmsFormWantTest::TearDown()
{
}

HWTEST_F(FmsFormWantTest, FormWant_Constructor_Default_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_Constructor_Default_001 start";
    FormWant formWant;
    EXPECT_FALSE(formWant.HasParameter("any_key"));
    EXPECT_FALSE(formWant.HasParameter("another_key"));
    Want want = formWant.GetWant();
    EXPECT_TRUE(want.GetParams().GetParams().empty());
    EXPECT_EQ(want.GetParams().GetParams().size(), 0);
    GTEST_LOG_(INFO) << "FormWant_Constructor_Default_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_Constructor_Want_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_Constructor_Want_001 start";
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 1);
    want.SetParam("external_param", 100);
    want.SetParam("key1", 1);
    FormWant formWant(want);
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(formWant.HasParameter("external_param"));
    EXPECT_TRUE(formWant.HasParameter("key1"));
    EXPECT_EQ(formWant.GetIntParam("key1", 0), 1);
    GTEST_LOG_(INFO) << "FormWant_Constructor_Want_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_Constructor_WantParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_Constructor_WantParams_001 start";
    FormWant formWant;
    formWant.SetParam("key1", 1);
    formWant.SetParam("key2", std::string("value"));
    EXPECT_TRUE(formWant.HasParameter("key1"));
    EXPECT_TRUE(formWant.HasParameter("key2"));
    GTEST_LOG_(INFO) << "FormWant_Constructor_WantParams_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetWant_GetWant_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetWant_GetWant_001 start";
    Want want;
    want.SetParam("test_key", 123);
    FormWant formWant;
    formWant = FormWant(want);
    Want result = formWant.GetWant();
    EXPECT_TRUE(formWant.HasParameter("test_key"));
    EXPECT_EQ(result.GetIntParam("test_key", 0), 123);
    GTEST_LOG_(INFO) << "FormWant_SetWant_GetWant_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_Int_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_Int_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 123);
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_EQ(formWant.GetIntParam(Constants::FORM_CONNECT_ID, 0), 123);
    formWant.SetParam("external_int", 456);
    EXPECT_EQ(formWant.GetIntParam("external_int", 0), 456);
    GTEST_LOG_(INFO) << "FormWant_SetParam_Int_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_Long_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_Long_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_SUPPLY_UID, 99999L);
    EXPECT_EQ(formWant.GetLongParam(Constants::FORM_SUPPLY_UID, 0L), 99999L);
    formWant.SetParam("external_long", 12345L);
    EXPECT_EQ(formWant.GetLongParam("external_long", 0L), 12345L);
    GTEST_LOG_(INFO) << "FormWant_SetParam_Long_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_String_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_String_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::PARAM_FORM_COLOR_MODE_KEY, std::string("dark"));
    EXPECT_EQ(formWant.GetStringParam(Constants::PARAM_FORM_COLOR_MODE_KEY), "dark");
    formWant.SetParam("external_string", std::string("value"));
    EXPECT_EQ(formWant.GetStringParam("external_string"), "value");
    GTEST_LOG_(INFO) << "FormWant_SetParam_String_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_Bool_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_Bool_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_ALLOW_UPDATE, true);
    EXPECT_TRUE(formWant.GetBoolParam(Constants::FORM_ALLOW_UPDATE, false));
    formWant.SetParam("external_bool", false);
    EXPECT_FALSE(formWant.GetBoolParam("external_bool", true));
    GTEST_LOG_(INFO) << "FormWant_SetParam_Bool_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetIntParam_DefaultValue_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetIntParam_DefaultValue_001 start";
    FormWant formWant;
    EXPECT_EQ(formWant.GetIntParam("nonexistent", 999), 999);
    EXPECT_EQ(formWant.GetIntParam("nonexistent", 0), 0);
    EXPECT_EQ(formWant.GetIntParam("nonexistent", -1), -1);
    formWant.SetParam("existing_key", 123);
    EXPECT_EQ(formWant.GetIntParam("existing_key", 999), 123);
    EXPECT_EQ(formWant.GetIntParam("existing_key", 0), 123);
    GTEST_LOG_(INFO) << "FormWant_GetIntParam_DefaultValue_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetStringParam_Empty_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetStringParam_Empty_001 start";
    FormWant formWant;
    EXPECT_EQ(formWant.GetStringParam("nonexistent"), "");
    formWant.SetParam("existing_key", std::string("test_value"));
    EXPECT_EQ(formWant.GetStringParam("existing_key"), "test_value");
    formWant.SetParam("empty_key", std::string(""));
    EXPECT_EQ(formWant.GetStringParam("empty_key"), "");
    EXPECT_EQ(formWant.GetStringParam("another_nonexistent"), "");
    GTEST_LOG_(INFO) << "FormWant_GetStringParam_Empty_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_RemoveParam_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_RemoveParam_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 1);
    formWant.SetParam("external_param", 100);
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(formWant.HasParameter("external_param"));
    formWant.RemoveParam(Constants::FORM_CONNECT_ID);
    formWant.RemoveParam("external_param");
    EXPECT_FALSE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_FALSE(formWant.HasParameter("external_param"));
    GTEST_LOG_(INFO) << "FormWant_RemoveParam_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_ChainedSetParam_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_ChainedSetParam_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 1)
        .SetParam("external_int", 2)
        .SetParam("external_string", std::string("value"))
        .SetParam(Constants::FORM_ALLOW_UPDATE, true);
    EXPECT_EQ(formWant.GetIntParam(Constants::FORM_CONNECT_ID, 0), 1);
    EXPECT_EQ(formWant.GetIntParam("external_int", 0), 2);
    EXPECT_EQ(formWant.GetStringParam("external_string"), "value");
    EXPECT_TRUE(formWant.GetBoolParam(Constants::FORM_ALLOW_UPDATE, false));
    GTEST_LOG_(INFO) << "FormWant_ChainedSetParam_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetFilteredWant_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetFilteredWant_001 start";
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 1);
    want.SetParam(Constants::ACQUIRE_TYPE, 2);
    want.SetParam("user_param", std::string("value"));
    FormWant formWant(want);
    Want filtered = formWant.GetFilteredWant();
    EXPECT_FALSE(filtered.GetParams().HasParam(Constants::FORM_CONNECT_ID));
    EXPECT_FALSE(filtered.GetParams().HasParam(Constants::ACQUIRE_TYPE));
    EXPECT_TRUE(filtered.GetParams().HasParam("user_param"));
    GTEST_LOG_(INFO) << "FormWant_GetFilteredWant_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetFilteredWant_Compatible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetFilteredWant_Compatible_001 start";
    Want want;
    want.SetParam(Constants::PROVIDER_FLAG, 1);
    want.SetParam(Constants::FORM_SUPPLY_UID, 100);
    want.SetParam("user_param", std::string("value"));
    FormWant formWant(want);
    Want filtered = formWant.GetFilteredWant();
    EXPECT_TRUE(filtered.GetParams().HasParam(Constants::PROVIDER_FLAG));
    EXPECT_TRUE(filtered.GetParams().HasParam(Constants::FORM_SUPPLY_UID));
    EXPECT_TRUE(filtered.GetParams().HasParam("user_param"));
    GTEST_LOG_(INFO) << "FormWant_GetFilteredWant_Compatible_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_FilterInternalParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_FilterInternalParams_001 start";
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 1);
    want.SetParam("external_param", 100);
    Want filtered = FormWant::FilterInternalParams(want);
    EXPECT_FALSE(filtered.GetParams().HasParam(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(filtered.GetParams().HasParam("external_param"));
    GTEST_LOG_(INFO) << "FormWant_FilterInternalParams_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_CopyConstructor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_CopyConstructor_001 start";
    FormWant original;
    original.SetParam(Constants::FORM_CONNECT_ID, 1);
    original.SetParam("external", std::string("value"));
    FormWant copy(original);
    EXPECT_TRUE(copy.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(copy.HasParameter("external"));
    EXPECT_EQ(copy.GetIntParam(Constants::FORM_CONNECT_ID, 0), 1);
    EXPECT_EQ(copy.GetStringParam("external"), "value");
    GTEST_LOG_(INFO) << "FormWant_CopyConstructor_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_CopyAssignment_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_CopyAssignment_001 start";
    FormWant original;
    original.SetParam(Constants::FORM_CONNECT_ID, 1);
    original.SetParam("external", std::string("value"));
    FormWant copy;
    copy = original;
    EXPECT_TRUE(copy.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(copy.HasParameter("external"));
    EXPECT_EQ(copy.GetIntParam(Constants::FORM_CONNECT_ID, 0), 1);
    EXPECT_EQ(copy.GetStringParam("external"), "value");
    GTEST_LOG_(INFO) << "FormWant_CopyAssignment_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetParam_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetParam_001 start";
    FormWant formWant;
    formWant.SetParam("test_key", 123);
    EXPECT_TRUE(formWant.HasParameter("test_key"));
    EXPECT_TRUE(formWant.HasParameter("test_key"));
    GTEST_LOG_(INFO) << "FormWant_GetParam_001 end";
}


HWTEST_F(FmsFormWantTest, FormWant_SetParam_Double_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_Double_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 123.456);
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_EQ(formWant.GetIntParam(Constants::FORM_CONNECT_ID, 0), 123);
    formWant.SetParam("external_double", 789.012);
    EXPECT_EQ(formWant.GetIntParam("external_double", 0), 789);
    GTEST_LOG_(INFO) << "FormWant_SetParam_Double_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_Float_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_Float_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::PARAM_FORM_COLOR_MODE_KEY, 123.456f);
    EXPECT_EQ(formWant.GetStringParam(Constants::PARAM_FORM_COLOR_MODE_KEY), "123.456");
    formWant.SetParam("external_float", 789.012f);
    EXPECT_EQ(formWant.GetStringParam("external_float"), "789.012");
    GTEST_LOG_(INFO) << "FormWant_SetParam_Float_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_SetParam_RemoteObject_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_SetParam_RemoteObject_001 start";
    FormWant formWant;
    sptr<IRemoteObject> remoteObject = nullptr;
    formWant.SetParam(Constants::PARAM_FORM_HOST_TOKEN, remoteObject);
    EXPECT_TRUE(formWant.HasParameter(Constants::PARAM_FORM_HOST_TOKEN));
    EXPECT_EQ(formWant.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN), nullptr);
    formWant.SetParam("external_remote", remoteObject);
    EXPECT_EQ(formWant.GetRemoteObject("external_remote"), nullptr);
    GTEST_LOG_(INFO) << "FormWant_SetParam_RemoteObject_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_MergeFrom_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_MergeFrom_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 1);
    formWant.SetParam("existing_param", std::string("value1"));
    EXPECT_TRUE(formWant.HasParameter("existing_param"));
    Want want;
    want.SetParam("new_param1", 100);
    want.SetParam("new_param2", std::string("value2"));
    want.SetParam(Constants::FORM_SUPPLY_UID, 999L);
    formWant.MergeFrom(want);
    EXPECT_TRUE(formWant.HasParameter("existing_param"));
    EXPECT_TRUE(formWant.HasParameter("new_param1"));
    EXPECT_TRUE(formWant.HasParameter("new_param2"));
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_SUPPLY_UID));
    EXPECT_EQ(formWant.GetStringParam("existing_param"), "value1");
    EXPECT_EQ(formWant.GetIntParam("new_param1", 0), 100);
    EXPECT_EQ(formWant.GetStringParam("new_param2"), "value2");
    EXPECT_EQ(formWant.GetLongParam(Constants::FORM_SUPPLY_UID, 0L), 999L);
    GTEST_LOG_(INFO) << "FormWant_MergeFrom_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_MergeWantParams_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_MergeWantParams_001 start";
    Want target;
    target.SetParam(Constants::FORM_CONNECT_ID, 1);
    target.SetParam("existing_param", std::string("value1"));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(target.GetParams().HasParam("existing_param"));
    Want source;
    source.SetParam("new_param1", 100);
    source.SetParam("new_param2", std::string("value2"));
    source.SetParam(Constants::FORM_SUPPLY_UID, 999L);
    FormWant::MergeWantParams(target, source);
    EXPECT_TRUE(target.GetParams().HasParam("new_param1"));
    EXPECT_TRUE(target.GetParams().HasParam("new_param2"));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::FORM_SUPPLY_UID));
    EXPECT_EQ(target.GetIntParam("new_param1", 0), 100);
    EXPECT_EQ(target.GetStringParam("new_param2"), "value2");
    EXPECT_EQ(target.GetLongParam(Constants::FORM_SUPPLY_UID, 0L), 999L);
    GTEST_LOG_(INFO) << "FormWant_MergeWantParams_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_ExtractHostParamsToWant_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_ExtractHostParamsToWant_001 start";
    FormWant formWant;
    formWant.SetParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY, true);
    formWant.SetParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY, std::string("blur"));
    formWant.SetParam(Constants::PARAM_FORM_DISABLE_UIFIRST_KEY, true);
    formWant.SetParam(Constants::FORM_ENABLE_MATERIAL_BACKGROUND_KEY, true);
    formWant.SetParam(Constants::FORM_STYLE_PARAMETERS_KEY, std::string("custom_style"));
    formWant.SetParam(Constants::FORM_ONE_MIRROR_CHANGE_KEY, std::string("mirror_change"));
    formWant.SetParam("non_host_param", std::string("value"));
    EXPECT_TRUE(formWant.HasParameter("param1"));
    Want target;
    formWant.ExtractHostParamsToWant(target);
    EXPECT_TRUE(target.GetParams().HasParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::PARAM_FORM_DISABLE_UIFIRST_KEY));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::FORM_ENABLE_MATERIAL_BACKGROUND_KEY));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::FORM_STYLE_PARAMETERS_KEY));
    EXPECT_TRUE(target.GetParams().HasParam(Constants::FORM_ONE_MIRROR_CHANGE_KEY));
    EXPECT_FALSE(target.GetParams().HasParam("non_host_param"));
    EXPECT_TRUE(formWant.GetBoolParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY, false));
    EXPECT_EQ(target.GetStringParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY), "blur");
    GTEST_LOG_(INFO) << "FormWant_ExtractHostParamsToWant_001 end";
}

HWTEST_F(FmsFormWantTest, FormWant_RemoveParam_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_RemoveParam_002 start";
    FormWant formWant;
    formWant.SetParam(Constants::FORM_CONNECT_ID, 1);
    formWant.SetParam(Constants::FORM_SUPPLY_UID, 100L);
    formWant.SetParam("external_param", std::string("value"));
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_SUPPLY_UID));
    EXPECT_TRUE(formWant.HasParameter("external_param"));
    formWant.RemoveParam(Constants::FORM_CONNECT_ID);
    EXPECT_FALSE(formWant.HasParameter(Constants::FORM_CONNECT_ID));
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_SUPPLY_UID));
    EXPECT_TRUE(formWant.HasParameter("external_param"));
    formWant.RemoveParam("external_param");
    EXPECT_FALSE(formWant.HasParameter("external_param"));
    EXPECT_TRUE(formWant.HasParameter(Constants::FORM_SUPPLY_UID));
    GTEST_LOG_(INFO) << "FormWant_RemoveParam_002 end";
}

HWTEST_F(FmsFormWantTest, FormWant_GetRemoteObject_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormWant_GetRemoteObject_001 start";
    FormWant formWant;
    sptr<IRemoteObject> remoteObject = nullptr;
    formWant.SetParam(Constants::PARAM_FORM_HOST_TOKEN, remoteObject);
    EXPECT_TRUE(formWant.HasParameter(Constants::PARAM_FORM_HOST_TOKEN));
    OHOS::sptr<OHOS::IRemoteObject> result = formWant.GetRemoteObject(Constants::PARAM_FORM_HOST_TOKEN);
    EXPECT_EQ(result, nullptr);
    sptr<IRemoteObject> nonexistent = formWant.GetRemoteObject("nonexistent_key");
    EXPECT_EQ(nonexistent, nullptr);
    GTEST_LOG_(INFO) << "FormWant_GetRemoteObject_001 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS