/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include <memory>
#define private public
#include "form_provider/connection/form_batch_delete_connection.h"
#undef private
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormBatchDeleteConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<FormBatchDeleteConnection> formBatchDeleteConnection_ = nullptr;
};

void FormBatchDeleteConnectionTest::SetUpTestCase()
{}

void FormBatchDeleteConnectionTest::TearDownTestCase()
{}

void FormBatchDeleteConnectionTest::SetUp()
{}

void FormBatchDeleteConnectionTest::TearDown()
{
    formBatchDeleteConnection_ = nullptr;
}
}  // namespace
