/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
const std::string BUNDLE_NAME = "com.example.test";

class FormBundleForbidMgrTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormBundleForbidMgr& formbundleforbidmgr = FormBundleForbidMgr::GetInstance();
};

void FormBundleForbidMgrTest::SetUp()
{
    OHOS::AppExecFwk::ElementName element;
    element.SetBundleName(BUNDLE_NAME);
}

void FormBundleForbidMgrTest::TearDown()
{
}

/**
 * @tc.name: formbundleforbidmgr_001
 * @tc.desc: test IsBundleForbidden function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleForbidMgrTest, formbundleforbidmgr_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "formbundleforbidmgr_001 begin";
    formbundleforbidmgr.Init();
    bool forbid = formbundleforbidmgr.IsBundleForbidden("");
    formbundleforbidmgr.IsBundleForbidden(BUNDLE_NAME);
    formbundleforbidmgr.SetBundleForbiddenStatus("", false);
    formbundleforbidmgr.SetBundleForbiddenStatus(BUNDLE_NAME, false);
    formbundleforbidmgr.SetBundleForbiddenStatus(BUNDLE_NAME, true);
    EXPECT_EQ(forbid, false);
    GTEST_LOG_(INFO) << "formbundleforbidmgr_001 end";
}
} // namespace