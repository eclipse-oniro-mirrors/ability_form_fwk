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
#include "feature/param_update/param_manager.h"
#include "feature/param_update/param_common_event.h"
#include "feature/param_update/param_reader.h"
#include "feature/param_update/sign_tools.h"
#include "form_constants.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string EVENT_INFO_TYPE = "type";
    const std::string CFG_UPDATED_ACTION = "usual.event.DUE_SA_CFG_UPDATED";
    const std::string PARAM_CONFIG_TYPE = "FormMgrConfig";
    const std::string PARAM_PRESET_PATH = "/system/etc/FormMgrConfig/";
}

class FmsParamManagerTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    ParamManager& paramManager = ParamManager::GetInstance();
    ParamCommonEvent& paramCommonEvent = ParamCommonEvent::GetInstance();
    ParamReader& paramReader = ParamReader::GetInstance();
};

void FmsParamManagerTest::SetUp()
{}

void FmsParamManagerTest::TearDown()
{}

/**
 * @tc.name: fmsParamManager_001
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_001 start";
    paramCommonEvent.SubscriberEvent();
    paramManager.InitParam();
    std::string paramStr = paramManager.GetParamStr();
    std::string version = paramManager.GetParamVersion();
    EXPECT_EQ(version.empty(), false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_001 end";
}

/**
 * @tc.name: fmsParamManager_002
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_002 start";
    paramCommonEvent.SubscriberEvent();
    AAFwk::Want want;
    paramCommonEvent.OnReceiveEvent(want);
    std::string version = paramManager.GetParamVersion();
    EXPECT_EQ(version.empty(), false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_002 end";
}

/**
 * @tc.name: fmsParamManager_003
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_003 start";
    AAFwk::Want want;
    want.SetAction(CFG_UPDATED_ACTION);
    paramCommonEvent.OnReceiveEvent(want);
    std::string version = paramManager.GetParamVersion();
    EXPECT_EQ(version.empty(), false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_003 end";
}

/**
 * @tc.name: fmsParamManager_004
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_004 start";
    AAFwk::Want want;
    want.SetAction(CFG_UPDATED_ACTION);
    want.SetParam(EVENT_INFO_TYPE, PARAM_CONFIG_TYPE);
    paramCommonEvent.OnReceiveEvent(want);
    std::string version = paramManager.GetParamVersion();
    paramCommonEvent.UnSubscriberEvent();
    EXPECT_EQ(version.empty(), false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_004 end";
}

/**
 * @tc.name: fmsParamManager_005
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_005 start";
    std::string path = "";
    std::string presetVersion = paramReader.GetPathVersion(path);
    EXPECT_EQ(presetVersion, Constants::FMC_DEFAULT_VERSION);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_005 end";
}

/**
 * @tc.name: fmsParamManager_006
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_006 start";
    bool result = paramReader.VerifyCertSfFile();
    std::string version = paramManager.GetParamVersion();
    EXPECT_EQ(version.empty(), false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_006 end";
}

/**
 * @tc.name: fmsParamManager_007
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_007 start";
    std::string path = "";
    bool result = paramReader.VerifyParamFile(path);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_007 end";
}

/**
 * @tc.name: fmsParamManager_008
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_008 start";
    std::string path = "";
    std::string param = paramReader.GetParamInfoStr(path);
    EXPECT_EQ(param.empty(), true);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_008 end";
}

/**
 * @tc.name: fmsParamManager_009
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsParamManagerTest, fmsParamManager_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_009 start";
    std::string path = PARAM_PRESET_PATH + Constants::VERSION_FILE_NAME;
    SignTools::CalcFileSha256Digest(path);
    path = "";
    std::tuple<int, std::string> ret = SignTools::CalcFileSha256Digest(path);
    EXPECT_NE(std::get<0>(ret), 0);
    GTEST_LOG_(INFO) << "FmsParamManagerTest fmsParamManager_009 end";
}
}
}