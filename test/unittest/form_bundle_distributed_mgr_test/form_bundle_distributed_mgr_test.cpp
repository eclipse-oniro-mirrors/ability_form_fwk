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
#include "feature/bundle_distributed/form_distributed_mgr.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
const std::string BUNDLE_NAME = "com.example.test";

class FormBundleDistributedMgrTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormDistributedMgr& bundleDistributedMgr_ = FormDistributedMgr::GetInstance();
};

void FormBundleDistributedMgrTest::SetUp() {}

void FormBundleDistributedMgrTest::TearDown() {}

/**
 * @tc.name: bundleDistributedMgr_001
 * @tc.desc: test IsBundleDistributed function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleDistributedMgrTest, bundleDistributedMgr_001, TestSize.Level1)
{
    EXPECT_EQ(bundleDistributedMgr_.IsBundleDistributed(""), false);
    EXPECT_EQ(bundleDistributedMgr_.IsBundleDistributed(BUNDLE_NAME), false);
}

/**
 * @tc.name: bundleDistributedMgr_002
 * @tc.desc: test SetBundleDistributedStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleDistributedMgrTest, bundleDistributedMgr_002, TestSize.Level1)
{
    DistributedModule distributedModule;
    bundleDistributedMgr_.SetBundleDistributedStatus("", true, distributedModule);
    bundleDistributedMgr_.SetBundleDistributedStatus(BUNDLE_NAME, true, distributedModule);
    EXPECT_EQ(bundleDistributedMgr_.IsBundleDistributed(BUNDLE_NAME), true);
    bundleDistributedMgr_.SetBundleDistributedStatus(BUNDLE_NAME, false, distributedModule);
    EXPECT_EQ(bundleDistributedMgr_.IsBundleDistributed(BUNDLE_NAME), false);
}
} // namespace