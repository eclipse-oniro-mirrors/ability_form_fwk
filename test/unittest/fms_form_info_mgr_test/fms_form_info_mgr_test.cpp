/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "extension_form_profile.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string JSON_NONE;
const std::string JSON_EMPTY = "{}";
const nlohmann::json JSON_BAD_FORMS = R"({"forms":""})"_json;
const nlohmann::json JSON_EMPTY_FORMS = R"({"forms":[]})"_json;
const nlohmann::json JSON_FORMS = R"(
{
    "privacyLevel": 0,
    "forms": [
        {
            "name": "Form_001",
            "description": "$string:form_description",
            "src": "./js/pages/card/index",
            "window": {
                "designWidth": 720,
                "autoDesignWidth": true
            },
            "colorMode": "auto",
            "formConfigAbility": "ability://form_ability_001",
            "formVisibleNotify": false,
            "isDefault": true,
            "updateEnabled": true,
            "scheduledUpdateTime": "10:30",
            "updateDuration": 1,
            "fontScaleFollowSystem": false,
            "defaultDimension": "2*2",
            "supportDimensions": ["2*2"],
            "metadata": [
                {
                    "name": "string",
                    "value": "string"
                }
            ]
        }, {
            "name": "Form_002",
            "formConfigAbility": "ability://form_ability_002",
            "isDefault": true,
            "updateEnabled": true,
            "defaultDimension": "2*2",
            "supportDimensions": ["2*2"]
        }
    ]
})"_json;
const int32_t JSON_FORMS_NUM = 2;

std::string JsonToString(const nlohmann::json &json)
{
    std::ostringstream stream;
    stream << json.dump();
    return stream.str();
}

HWTEST(ExtensionFormProfileTest, TransformTo_0100, TestSize.Level0)
{
    // the form data privacy level
    int32_t level = -1;
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    // none profile
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_BAD_PROFILE,
        ExtensionFormProfile::TransformTo(JSON_NONE, extensionFormInfos, level));
    EXPECT_EQ(0, extensionFormInfos.size());
    // empty profile
    EXPECT_EQ(ERR_OK, ExtensionFormProfile::TransformTo(JSON_EMPTY, extensionFormInfos, level));
    EXPECT_EQ(0, extensionFormInfos.size());
    // bad forms profile
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(JSON_BAD_FORMS), extensionFormInfos, level));
    EXPECT_EQ(0, extensionFormInfos.size());
    // empty forms profile
    EXPECT_EQ(ERR_OK, ExtensionFormProfile::TransformTo(JsonToString(JSON_EMPTY_FORMS), extensionFormInfos, level));
    EXPECT_EQ(0, extensionFormInfos.size());
    // forms ok profile for no privacy level setting
    EXPECT_EQ(ERR_OK, ExtensionFormProfile::TransformTo(JsonToString(JSON_FORMS), extensionFormInfos, level));
    EXPECT_EQ(JSON_FORMS_NUM, extensionFormInfos.size());
}

HWTEST(ExtensionFormProfileTest, TransformTo_0101, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    std::vector<std::string> notMustPropKeys = {
        ExtensionFormProfileReader::DESCRIPTION,
        ExtensionFormProfileReader::SRC,
        ExtensionFormProfileReader::WINDOW,
        ExtensionFormProfileReader::COLOR_MODE,
        ExtensionFormProfileReader::FORM_CONFIG_ABILITY,
        ExtensionFormProfileReader::FORM_VISIBLE_NOTIFY,
        ExtensionFormProfileReader::SCHEDULED_UPDATE_TIME,
        ExtensionFormProfileReader::UPDATE_DURATION,
        ExtensionFormProfileReader::METADATA
    };
    for (const auto &prop: notMustPropKeys) {
        nlohmann::json formsJson = JSON_FORMS;
        formsJson[ExtensionFormProfileReader::FORMS][0].erase(prop);
        numForms += JSON_FORMS_NUM;
        EXPECT_EQ(ERR_OK, ExtensionFormProfile::TransformTo(JsonToString(formsJson), extensionFormInfos, level));
        EXPECT_EQ(numForms, extensionFormInfos.size());
        EXPECT_EQ(0, level);
    }

    std::vector<std::string> mustPropKeys = {
        ExtensionFormProfileReader::NAME,
        ExtensionFormProfileReader::IS_DEFAULT,
        ExtensionFormProfileReader::UPDATE_ENABLED,
        ExtensionFormProfileReader::DEFAULT_DIMENSION,
        ExtensionFormProfileReader::SUPPORT_DIMENSIONS
    };
    for (const auto &prop: mustPropKeys) {
        nlohmann::json errorJson = JSON_FORMS;
        errorJson[ExtensionFormProfileReader::FORMS][0].erase(prop);
        EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP,
            ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
        EXPECT_EQ(numForms, extensionFormInfos.size());
        EXPECT_EQ(0, level);
    }
}

HWTEST(ExtensionFormProfileTest, TransformTo_0102, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // name
    nlohmann::json errorJson = JSON_FORMS;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::NAME] = "";
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);
    // max name size
    const int32_t maxFormName = 128;
    std::string maxName(maxFormName, 'a');
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::NAME] = maxName;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0103, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0104, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0105, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0106, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0107, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0108, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0109, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0110, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0111, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0112, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0113, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0114, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0115, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0116, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0117, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0118, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0119, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0120, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0121, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0122, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0123, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0124, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0125, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0126, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0127, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0128, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0129, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0130, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0131, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0132, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0133, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0134, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0135, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0136, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0137, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0138, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

HWTEST(ExtensionFormProfileTest, TransformTo_0139, TestSize.Level0)
{
    std::vector<ExtensionFormInfo> extensionFormInfos {};
    int32_t level = -1;
    int32_t numForms = 0;

    // dimension
    nlohmann::json errorJson = JSON_FORMS;
    const std::string invalidDimension = "1*4";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = invalidDimension;
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::SUPPORT_DIMENSIONS].push_back(
        invalidDimension);
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(numForms, extensionFormInfos.size());
    EXPECT_EQ(0, level);

    // not in support
    errorJson = JSON_FORMS;
    const std::string validDimension = "1*2";
    errorJson[ExtensionFormProfileReader::FORMS][0][ExtensionFormProfileReader::DEFAULT_DIMENSION] = validDimension;
    EXPECT_EQ(ERR_APPEXECFWK_PARSE_PROFILE_PROP_CHECK_ERROR,
        ExtensionFormProfile::TransformTo(JsonToString(errorJson), extensionFormInfos, level));
    EXPECT_EQ(0, level);
}

}  // namespace
