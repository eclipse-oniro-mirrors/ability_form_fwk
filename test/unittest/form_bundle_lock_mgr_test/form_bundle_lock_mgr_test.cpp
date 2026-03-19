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
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#undef private
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
const std::string BUNDLE_NAME = "com.example.test";

class FormBundleLockMgrTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormBundleLockMgr& formBundleLockMgr = FormBundleLockMgr::GetInstance();
};

void FormBundleLockMgrTest::SetUp()
{
    OHOS::AppExecFwk::ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    formBundleLockMgr.isLockServiceInitialized_.store(true);
}

void FormBundleLockMgrTest::TearDown()
{
}

/**
 * @tc.name: formBundleLockMgr_001
 * @tc.desc: test IsBundleLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_001, TestSize.Level1)
{
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, false);
    bool forbid = formBundleLockMgr.IsBundleLock(BUNDLE_NAME);
    EXPECT_EQ(forbid, false);
}

/**
 * @tc.name: formBundleLockMgr_002
 * @tc.desc: test SetBundleLockStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_002, TestSize.Level1)
{
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, true);
    bool forbid = formBundleLockMgr.IsBundleLock(BUNDLE_NAME);
    EXPECT_EQ(forbid, true);
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, false);
}

/**
 * @tc.name: formBundleLockMgr_IsBundleProtect_001
 * @tc.desc: test IsBundleProtect function, when bundleName is not protected.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_IsBundleProtect_001, TestSize.Level1)
{
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, false);
    bool forbid = formBundleLockMgr.IsBundleProtect(BUNDLE_NAME);
    EXPECT_EQ(forbid, false);
}

/**
 * @tc.name: formBundleLockMgr_IsBundleProtect_002
 * @tc.desc: test IsBundleProtect function, when bundleName is protected.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_IsBundleProtect_002, TestSize.Level1)
{
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, true);
    bool forbid = formBundleLockMgr.IsBundleProtect(BUNDLE_NAME);
    EXPECT_EQ(forbid, true);
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, false);
}

/**
 * @tc.name: formBundleLockMgr_005
 * @tc.desc: test IsBundleLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_005, TestSize.Level1)
{
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, false);
    bool forbid = formBundleLockMgr.IsBundleLock(BUNDLE_NAME);
    EXPECT_EQ(forbid, false);
}

/**
 * @tc.name: formBundleLockMgr_006
 * @tc.desc: test SetBundleLockStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_006, TestSize.Level1)
{
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, true);
    bool forbid = formBundleLockMgr.IsBundleLock(BUNDLE_NAME);
    EXPECT_EQ(forbid, true);
    formBundleLockMgr.SetBundleLockStatus(BUNDLE_NAME, false);
}

/**
 * @tc.name: formBundleLockMgr_007
 * @tc.desc: test IsBundleProtect function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_007, TestSize.Level1)
{
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, false);
    bool forbid = formBundleLockMgr.IsBundleProtect(BUNDLE_NAME);
    EXPECT_EQ(forbid, false);
}

/**
 * @tc.name: formBundleLockMgr_008
 * @tc.desc: test SetBundleProtectStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_008, TestSize.Level1)
{
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, true);
    bool forbid = formBundleLockMgr.IsBundleProtect(BUNDLE_NAME);
    EXPECT_EQ(forbid, true);
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, false);
}

/**
 * @tc.name: formBundleLockMgr_IsBundleProtect_003
 * @tc.desc: test IsBundleProtect function, when isLockServiceInitialized_ is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_IsBundleProtect_003, TestSize.Level1)
{
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, true);
    int32_t userId = DEFAULT_USER_ID;
    formBundleLockMgr.isLockServiceInitialized_.store(false);
    bool forbid = formBundleLockMgr.IsBundleProtect(BUNDLE_NAME, userId);
    formBundleLockMgr.isLockServiceInitialized_.store(true);
    EXPECT_EQ(forbid, false);
    formBundleLockMgr.SetBundleProtectStatus(BUNDLE_NAME, false);
}

/**
 * @tc.name: formBundleLockMgr_InitLockService_001
 * @tc.desc: test InitLockService function.
 * @tc.type: FUNC
 */
HWTEST_F(FormBundleLockMgrTest, formBundleLockMgr_InitLockService_001, TestSize.Level1)
{
    formBundleLockMgr.isLockServiceInitialized_.store(false);
    formBundleLockMgr.InitLockService();
    // test isLockServiceInitialized_ is false
    EXPECT_TRUE(formBundleLockMgr.isLockServiceInitialized_.load());
    // test isLockServiceInitialized_ is true
    EXPECT_TRUE(formBundleLockMgr.isLockServiceInitialized_.load());
}
} // namespace