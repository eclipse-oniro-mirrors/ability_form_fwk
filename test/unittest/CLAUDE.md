# CLAUDE.md - Form Framework Unit Testing Guide

This guide is for unit testing in the form_fwk (Form Framework) codebase.

## Unit Testing Overview

Unit testing is a software testing method where individual units of source code are tested to determine whether they are fit for use. This project uses Google Test (gtest) framework for unit testing.

## Unit Test Structure

Each unit test directory should contain the following files:
- `<module>_test.cpp` - Main test implementation
- `BUILD.gn` - Build configuration
- Optional: mock files for testing external dependencies

## Creating a New Unit Test

### Directory Structure
```bash
test/unittest/fms_form_<module>_test/
├── BUILD.gn
└── fms_form_<module>_test.cpp
```

### Test File Template
```cpp
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
#include "path/to/class_under_test.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FmsForm<ModuleName>Test : public testing::Test {
public:
    static void SetUpTestCase();
    
    static void TearDownTestCase();
    
    void SetUp();
    
    void TearDown();
};

void FmsForm<ModuleName>Test::SetUpTestCase() {
    // Setup code that runs once before all tests
}

void FmsForm<ModuleName>Test::TearDownTestCase() {
    // Cleanup code that runs once after all tests
}

void FmsForm<ModuleName>Test::SetUp() {
    // Setup code that runs before each test
}

void FmsForm<ModuleName>Test::TearDown() {
    // Cleanup code that runs after each test
}

/**
 * @tc.name: FmsForm<ModuleName>Test_001
 * @tc.desc: Verify function <FunctionName>.
 * @tc.type: FUNC
 */
HWTEST_F(FmsForm<ModuleName>Test, FmsForm<ModuleName>Test_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsForm<ModuleName>Test_001 begin";
    
    // Test code here
    
    GTEST_LOG_(INFO) << "FmsForm<ModuleName>Test_001 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
```

### BUILD.gn Template
```gn
# Copyright (c) 2024 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import("//build/test.gni")
import("//foundation/ability/form_fwk/form_fwk.gni")

module_output_path = "form_fwk/form_fwk/form_mgr_service"

ohos_unittest("FmsForm<ModuleName>Test") {
  module_out_path = module_output_path
  
  sources = [
    "${form_fwk_path}/services/src/path/to/source.cpp",
    "${form_fwk_path}/test/unittest/fms_form_<module>_test/fms_form_<module>_test.cpp",
  ]
  
  include_dirs = [
    "${form_fwk_path}/interfaces/inner_api/include",
    "${form_fwk_path}/services/include",
  ]
  
  configs = []
  cflags = []
  
  if (target_cpu == "arm") {
    cflags += [ "-DBINDER_IPC_32BIT" ]
  }
  
  deps = [
    "${form_fwk_path}:fms_target",
    "${form_fwk_path}:fmskit_native",
  ]
  
  external_deps = [
    "ability_runtime:app_manager",
    "c_utils:utils",
    "ffrt:libffrt",
    "form_fwk:form_manager",
    "hilog:libhilog",
    "huks:libhukssdk",
    "ipc:ipc_core",
    "safwk:system_ability_fwk",
    "samgr:samgr_proxy",
  ]
}

###############################################################################
group("unittest") {
  testonly = true
  
  deps = [ ":FmsForm<ModuleName>Test" ]
}
###############################################################################
```

## Test Naming Conventions

- Test class name: `Fms<ModuleName>Test` (e.g., `FmsFormMgrTest`, `FmsFormDataMgrTest`)
- Test case name: `FmsForm<ModuleName>Test_<XXX>` with incrementing numbers
- Test size level: `TestSize.Level0` (smoke), `TestSize.Level1` (basic), `TestSize.Level2` (full)

## GTest Macros and Assertions

### Test Macros
- `HWTEST_F(TestFixture, TestName, TestSize)` - Hardware test macro
- `GTEST_LOG_(INFO)` - Test logging

### Assertions
- `EXPECT_EQ(expected, actual)` - Equality check (non-fatal)
- `EXPECT_NE(val1, val2)` - Inequality check (non-fatal)
- `EXPECT_TRUE(condition)` - Boolean true check (non-fatal)
- `EXPECT_FALSE(condition)` - Boolean false check (non-fatal)
- `EXPECT_STREQ(str1, str2)` - String equality (non-fatal)
- `EXPECT_GT(val1, val2)` - Greater than (non-fatal)
- `EXPECT_LT(val1, val2)` - Less than (non-fatal)

- `ASSERT_EQ(expected, actual)` - Equality check (fatal, stops test)
- `ASSERT_NE(val1, val2)` - Inequality check (fatal, stops test)
- `ASSERT_TRUE(condition)` - Boolean true check (fatal, stops test)
- `ASSERT_FALSE(condition)` - Boolean false check (fatal, stops test)
- `ASSERT_STREQ(str1, str2)` - String equality (fatal, stops test)

## Test Documentation Format

Each test should have a comment block:
```cpp
/**
 * @tc.name: TestClassName_TestNumber
 * @tc.desc: Verify function <FunctionName> with specific conditions.
 * @tc.type: FUNC
 * @tc.require: AR-xxxxx
 * @tc.author: xxx
 * @tc.level: Level0/Level1/Level2
 */
```

## Testing Private Members

To test private or protected members, use these macros:
```cpp
#define private public
#define protected public
#include "class_under_test.h"
#undef private
#undef protected
```

## Using Mock Objects

Mock classes are available in `test/mock/include/`:
- `MockForm<ClassName>` - Mock implementations for testing
- `MockIRemoteObject` - Mock IPC objects

Example usage:
```cpp
#include "test/mock/include/mock_form_mgr_service.h"

void SetUp() {
    mockService_ = new MockFormMgrService();
}
```

## Common Test Patterns

### Testing Return Values
```cpp
HWTEST_F(FmsFormMgrTest, FmsFormMgrTest_GetFormId_001, TestSize.Level1)
{
    int64_t formId = formMgr_->GetFormId();
    EXPECT_GT(formId, 0);
}
```

### Testing Error Conditions
```cpp
HWTEST_F(FmsFormMgrTest, FmsFormMgrTest_AddForm_InvalidParam_002, TestSize.Level1)
{
    Want want;
    ErrCode ret = formMgr_->AddForm(want, nullptr);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}
```

### Testing with Mocks
```cpp
HWTEST_F(FmsFormMgrTest, FmsFormMgrTest_NotifyFormUpdate_003, TestSize.Level1)
{
    EXPECT_CALL(*mockObserver_, OnFormUpdated(_)).Times(1);
    formMgr_->NotifyFormUpdate(formId);
}
```

## Running Unit Tests

```bash
# Build all unit tests
./build.sh --product-name <product> --build-target //foundation/ability/form_fwk/test:unittest

# Run all unit tests
./build.sh --product-name <product> --test-case unittest

# Run specific test
./build.sh --product-name <product> --test-name FmsFormMgrTest

# Run specific test case
./build.sh --product-name <product> --test-case FmsFormMgrTest.FmsFormMgrTest_001
```

## Existing Unit Tests

The following unit test modules are available in the codebase:

- `fms_form_ability_connection_reporter_test` - Tests FormAbilityConnectionReporter
- `fms_form_abnormal_reporter_test` - Tests FormAbnormalReporter
- `fms_form_ams_helper_test` - Tests FormAmsHelper
- `fms_form_ashmem_test` - Tests FormAshmem
- `fms_form_cache_mgr_test` - Tests FormCacheMgr
- `fms_form_caller_mgr_test` - Tests FormCallerMgr
- `fms_form_data_mgr_test` - Tests FormDataMgr
- `fms_form_db_info_test` - Tests FormDBInfo
- `fms_form_db_record_test` - Tests FormDBRecord
- `fms_form_distributed_client_test` - Tests FormDistributedClient
- `fms_form_event_notify_connection_test` - Tests FormEventNotifyConnection
- `fms_form_event_report_test` - Tests FormEventReport
- `fms_form_host_callback_test` - Tests FormHostCallback
- `fms_form_host_client_test` - Tests FormHostClient
- `fms_form_host_proxy_test` - Tests FormHostProxy
- `fms_form_info_mgr_test` - Tests FormInfoMgr
- `fms_form_instance_test` - Tests FormInstance
- `fms_form_js_info_test` - Tests FormJsInfo
- `fms_form_mgr_test` - Tests FormMgr
- `fms_form_provider_client_test` - Tests FormProviderClient
- `fms_form_provider_mgr_test` - Tests FormProviderMgr
- `fms_form_provider_proxy_test` - Tests FormProviderProxy
- `fms_form_refresh_connection_test` - Tests FormRefreshConnection
- `fms_form_render_mgr_test` - Tests FormRenderMgr
- `fms_form_render_proxy_test` - Tests FormRenderProxy
- `fms_form_share_mgr_test` - Tests FormShareMgr
- `fms_form_supply_callback_test` - Tests FormSupplyCallback
- `fms_form_supply_proxy_test` - Tests FormSupplyProxy
- `fms_form_sys_event_receiver_test` - Tests FormSysEventReceiver
- `fms_form_timer_mgr_test` - Tests FormTimerMgr
- `fms_form_util_test` - Tests FormUtil
- `fms_param_manager_test` - Tests ParamManager
- `fms_provider_connect_proxy_test` - Tests ProviderConnectProxy
- ... (see test/unittest for complete list)

## Common External Dependencies

Most unit tests will need these external dependencies:
- `ability_runtime:app_manager` - Ability manager for testing ability lifecycle
- `c_utils:utils` - Common utilities
- `ffrt:libffrt` - Function runtime for task scheduling
- `form_fwk:form_manager` - Form manager dependency
- `hilog:libhilog` - Logging
- `huks:libhukssdk` - HUKS for cryptographic operations
- `ipc:ipc_core` - IPC framework
- `safwk:system_ability_fwk` - System ability framework
- `samgr:samgr_proxy` - System ability manager

Additional dependencies may be needed based on the module being tested:
- `bundle_framework:appexecfwk_base` - Bundle framework base
- `bundle_framework:appexecfwk_core` - Bundle framework core
- `ability_base:base` - Base ability framework
- `ability_base:want` - Want message passing
- `openssl:libcrypto_shared` - For cryptographic operations
- `openssl:libssl_shared` - For SSL/TLS operations

## Best Practices

1. **Test Public APIs**: Focus on testing public interfaces
2. **Use Descriptive Names**: Test names should clearly describe what is being tested
3. **Test Happy Path**: Verify normal operation succeeds
4. **Test Error Paths**: Verify error handling works correctly
5. **Test Edge Cases**: Test boundary conditions and null/empty inputs
6. **Use Mocks**: Mock external dependencies to isolate the unit under test
7. **Clean Up Resources**: Use TearDown to release resources
8. **Keep Tests Independent**: Each test should be runnable independently
9. **Use Appropriate Assertions**: Use ASSERT for critical failures, EXPECT for non-critical
10. **Verify Test Results**: Each test case should have result comparison to verify test effectiveness
11. **Add Test Documentation**: Include @c.name, @tc.desc, @tc.type, @tc.level

## Test Size Levels

- **Level0 (Smoke)**: Quick sanity tests, verify basic functionality
- **Level1 (Basic)**: Core functionality tests, cover main use cases
- **Level2 (Full)**: Comprehensive tests, cover edge cases and error conditions

## Debugging Failed Tests

```bash
# Run with verbose output
./build.sh --product-name <product> --test-case FmsFormMgrTest --gtest-filter="*" --gtest_print_time=1

# Run with detailed failure info
./build.sh --product-name <product> --test-case FmsFormMgrTest --gtest_break_on_failure=1
```
