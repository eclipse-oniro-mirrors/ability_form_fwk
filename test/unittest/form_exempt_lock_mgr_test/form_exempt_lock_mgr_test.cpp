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
#include "form_exempt_lock_mgr.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
constexpr int64_t FORM_ID = 999;

class FormExemptLockMgrTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormExemptLockMgr& formExemptLockMgr = FormExemptLockMgr::GetInstance();
};

void FormExemptLockMgrTest::SetUp()
{}

void FormExemptLockMgrTest::TearDown()
{}

/**
 * @tc.name: formExemptLockMgr_001
 * @tc.desc: test IsExemptLock function.
 * @tc.type: FUNC
 */
HWTEST_F(FormExemptLockMgrTest, formExemptLockMgr_001, TestSize.Level1)
{
    formExemptLockMgr.SetExemptLockStatus(FORM_ID, false);
    bool exempt = formExemptLockMgr.IsExemptLock(FORM_ID);
    EXPECT_EQ(exempt, false);
}

/**
 * @tc.name: formExemptLockMgr_002
 * @tc.desc: test SetExemptLockStatus function.
 * @tc.type: FUNC
 */
HWTEST_F(FormExemptLockMgrTest, formExemptLockMgr_002, TestSize.Level1)
{
    formExemptLockMgr.SetExemptLockStatus(FORM_ID, true);
    bool exempt = formExemptLockMgr.IsExemptLock(FORM_ID);
    EXPECT_EQ(exempt, true);
    formExemptLockMgr.SetExemptLockStatus(FORM_ID, false);
}
} // namespace