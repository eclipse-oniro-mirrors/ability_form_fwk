# CLAUDE.md - Form Framework Fuzz Testing Guide

This guide is for fuzz testing in the form_fwk (Form Framework) codebase.

## Fuzz Testing Overview

Fuzz testing is a software testing technique that uses automated input generation to find bugs and vulnerabilities in code. This project uses libFuzzer for fuzz testing.

## Fuzz Test Structure

Each fuzz test directory should contain the following files:
- `*_fuzzer.cpp` - Main fuzz test implementation
- `*_fuzzer.h` - Header file with project name definition
- `BUILD.gn` - Build configuration
- `project.xml` - Fuzz configuration (max length, time, memory limits)
- `corpus/` - Directory for seed inputs (optional)

## Creating a New Fuzz Test

### Directory Structure
```bash
test/fuzztest/<module>_fuzzer/
├── BUILD.gn
├── <module>_fuzzer.cpp
├── <module>_fuzzer.h
├── corpus/
└── project.xml
```

### Header File Template
```cpp
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

#ifndef OHOS_FORM_FWK_<MODULE>_FUZZER_H
#define OHOS_FORM_FWK_<MODULE>_FUZZER_H

#define FUZZ_PROJECT_NAME "<module>_fuzzer"

#endif // OHOS_FORM_FWK_<MODULE>_FUZZER_H
```

### Fuzzer Implementation Template
```cpp
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

#include "<module>_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "path/to/class_under_test.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = -10000;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // Generate fuzzed inputs
    std::string str1 = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    int32_t num = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    bool flag = fdp->ConsumeBool();

    // Call methods to test
    // ...

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
```

### BUILD.gn Template
```gn
# Copyright (c) 2026 Huawei Device Co., Ltd.
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

#####################hydra-fuzz###################
import("//build/config/features.gni")
import("//build/ohos.gni")
import("//build/test.gni")
import("//foundation/ability/form_fwk/form_fwk.gni")

##############################fuzztest##########################################
ohos_fuzztest("<Module>FuzzTest") {
  module_out_path = form_fuzz_test_path

  fuzz_config_file = "${form_fwk_path}/test/fuzztest/<module>_fuzzer"

  include_dirs = [
    "${form_fwk_path}/interfaces/kits/native/include",
    "${form_fwk_path}/interfaces/inner_api/include",
    "${form_fwk_path}/services/include",
  ]
  cflags = [
    "-g",
    "-O0",
    "-Wno-unused-variable",
    "-fno-omit-frame-pointer",
  ]
  sources = [
    "<module>_fuzzer.cpp"
  ]

  deps = [
    "${form_fwk_path}:fms_target",
    "${form_fwk_path}:fmskit_native",
    "${form_fwk_path}:form_manager",
    "${form_fwk_path}:libfms",
  ]

  external_deps = [
    "ability_base:base",
    "ability_base:want",
    "bundle_framework:appexecfwk_base",
    "bundle_framework:appexecfwk_core",
    "c_utils:utils",
    "hilog:libhilog",
    "ipc:ipc_core",
    "samgr:samgr_proxy",
  ]
}

###############################################################################
group("fuzztest") {
  testonly = true
  deps = []
  deps += [
    # deps file
    ":<Module>FuzzTest",
  ]
}
###############################################################################
```

### project.xml Template
```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- Copyright (c) 2026 Huawei Device Co., Ltd.

     Licensed under the Apache License, Version 2.0 (the "License");
     you may not use this file except in compliance with the License.
     You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

     Unless required by applicable law or agreed to in writing, software
     distributed under the License is distributed on an "AS IS" BASIS,
     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
     See the License for the specific language governing permissions and
     limitations under the License.
-->
<fuzz_config>
  <fuzztest>
    <!-- maximum length of a test input -->
    <max_len>1000</max_len>
    <!-- maximum total time in seconds to run the fuzzer -->
    <max_total_time>200</max_total_time>
    <!-- memory usage limit in Mb -->
    <rss_limit_mb>4096</rss_limit_mb>
  </fuzztest>
</fuzz_config>
```

## Adding Fuzz Test to Build System

After creating a new fuzz test directory, add it to `test/fuzztest/BUILD.gn`:

```gn
group("fuzztest") {
  testonly = true
  
  deps = [
    # ... existing fuzz tests ...
    "<module>_fuzzer:fuzztest",
  ]
  
  # ... conditional deps ...
}
```

## FuzzedDataProvider Usage

The `FuzzedDataProvider` class provides methods to generate fuzzed data:

- `ConsumeBool()` - Consume a boolean value
- `ConsumeIntegral<T>()` - Consume an integral value of type T
- `ConsumeIntegralInRange(min, max)` - Consume an integral value in range
- `ConsumeRandomLengthString(maxLen)` - Consume a random length string
- `ConsumeBytes(count)` - Consume count bytes
- `ConsumeRemainingBytes()` - Consume all remaining bytes

## Best Practices

1. **Test All Public Methods**: Ensure fuzz tests cover all public methods of the target class
2. **Use Random Inputs**: Generate varied inputs including edge cases
3. **Handle Null Checks**: Test with null pointers and empty strings
4. **Test Error Paths**: Verify error handling works correctly
5. **Keep Tests Focused**: Each fuzz test should focus on one class or module
6. **Use Appropriate Constants**: Define MAX_LENGTH, MAX_NUM, MIN_NUM for input bounds
7. **Avoid Crashes**: Fuzz tests should not crash on any input

## Running Fuzz Tests

```bash
# Build fuzz tests
./build.sh --product-name <product> --build-target //foundation/ability/form_fwk/test:fuzztest

# Run specific fuzz test
./build.sh --product-name <product> --test-case <Module>FuzzTest
```

## Existing Fuzz Tests

The following fuzz tests are available in the codebase:

- `bundleforminfo_fuzzer` - Tests BundleFormInfo class
- `forminfostorage_fuzzer` - Tests FormInfoStorage struct
- `signtools_fuzzer` - Tests SignTools class
- `forminfomgr_fuzzer` - Tests FormInfoMgr class
- `formrenderservicemgr_fuzzer` - Tests FormRenderServiceMgr class
- ... (see test/fuzztest/BUILD.gn for complete list)

## Common External Dependencies

Most fuzz tests will need these external dependencies:
- `ability_base:base` - Base ability framework
- `ability_base:want` - Want message passing
- `bundle_framework:appexecfwk_base` - Bundle framework base
- `bundle_framework:appexecfwk_core` - Bundle framework core
- `c_utils:utils` - Common utilities
- `hilog:libhilog` - Logging
- `ipc:ipc_core` - IPC framework
- `samgr:samgr_proxy` - System ability manager

Additional dependencies may be needed based on the module being tested:
- `openssl:libcrypto_shared` - For cryptographic operations
- `openssl:libssl_shared` - For SSL/TLS operations
- `libxml2:libxml2` - For XML parsing
- `ffrt:libffrt` - For task scheduling
- `graphic_2d:librender_service_client` - For graphics
- `ace_engine:ace_form_render` - For ACE rendering
