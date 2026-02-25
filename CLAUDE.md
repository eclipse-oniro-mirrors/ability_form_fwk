# CLAUDE.md - Form Framework Development Guide

This guide is for Claude AI working in the form_fwk (Form Framework) codebase.

 
## Build System

This project uses GN (Generate Ninja) build system for OpenHarmony.

### Build Commands
```bash
# Build all targets
./build.sh --product-name <product> --build-target form_fwk

# Build specific library
./build.sh --product-name <product> --build-target //foundation/ability/form_fwk:libfms

# Build unit tests
./build.sh --product-name <product> --build-target //foundation/ability/form_fwk/test:unittest

# Run single unit test (example)
./build.sh --product-name <product> --test-name FmsFormMgrTest
```

### Test Commands
```bash
# Run specific test
./build.sh --product-name <product> --test-case FmsFormMgrTest
```

## Code Style Guidelines

### File Naming
- Source files: `snake_case.cpp` (e.g., `form_mgr_service.cpp`, `form_util.cpp`)
- Header files: `snake_case.h` (e.g., `form_mgr_interface.h`, `form_util.h`)
- Test files: `<module>_test.cpp` (e.g., `form_mgr_test.cpp`)

### Naming Conventions
- Classes: PascalCase (e.g., `FormMgrService`, `FormUtil`, `FormRefreshMgr`)
- Functions/Methods: PascalCase for public methods (e.g., `GenerateFormId`, `AddForm`, `DeleteForm`)
- Variables: camelCase for local variables, snake_case for member variables
- Constants: UPPER_SNAKE_CASE (e.g., `MAIN_USER_ID`, `API_TIME_OUT`)
- Enums: PascalCase with UPPER_SNAKE_CASE values (e.g., `ERR_APPEXECFWK_FORM_INVALID_PARAM`)
- Namespaces: `OHOS::AppExecFwk`

### File Structure
- License header at top (Apache 2.0)
- Include guards: `#ifndef OHOS_FORM_FWK_FILENAME_H`
- System includes first, then project includes
- Namespace: `OHOS::AppExecFwk`
- Anonymous namespace for file-local constants and helpers

### Imports and Includes
```cpp
// System includes first
#include <chrono>
#include <memory>

// Project includes with full paths
#include "form_mgr/form_mgr_service.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
```

### Error Handling
- Use error codes from `form_mgr_errors.h`
- Internal errors: `ERR_APPEXECFWK_FORM_*` (starting with 2293761)
- External errors: `ERR_FORM_EXTERNAL_*` (starting with 201)
- Always check return values from IPC calls
- Use `HILOG_ERROR` for error logging with context

### Logging
Use custom logging macros from `fms_log_wrapper.h`:
```cpp
HILOG_DEBUG("debug message: %{public}s", str);
HILOG_INFO("info message: %{public}d", value);
HILOG_WARN("warning message");
HILOG_ERROR("error message: %{public}s", error);
HILOG_FATAL("fatal message");
```

### Smart Pointers and IPC
- Use `sptr<T>` for IPC remote objects (e.g., `sptr<IRemoteObject>`, `sptr<IFormMgr>`)
- Use `wptr<T>` for weak references
- Use `std::shared_ptr<T>` and `std::unique_ptr<T>` for regular C++ objects

### Threading and Synchronization
- Use `std::mutex` for mutual exclusion
- Use `std::lock_guard<std::mutex>` for RAII-style locking
- Use `std::condition_variable` for condition waiting
- Avoid global mutable state; use static class members with proper synchronization

### Constants and Magic Numbers
- Define constants in anonymous namespace at file scope
- Use `constexpr` for compile-time constants
- Use `const char*` for constant of string type
- Document units (milliseconds, nanoseconds, etc.) in

### Comments and Documentation
- Doxygen-style comments for public APIs
- Brief comments for complex logic
- No comments for obvious code
- Example:
```cpp
/**
 * @brief Generate unique form ID
 * @param udidHash Device UDID hash
 * @return Generated form ID
 */
static int64_t GenerateFormId(int64_t udidHash);
```

### Testing Guidelines
- Use gtest and gmock frameworks
- Test class naming: `<Module>Test` (e.g., `FormMgrTest`)
- Use `#define private public` and `#define protected public` for testing private members
- Use mock classes from `test/mock/include/`
- Test fixtures: `SetUpTestCase()`, `TearDownTestCase()`, `SetUp()`, `TearDown()`
- Use `EXPECT_*` for non-critical assertions, `ASSERT_*` for critical ones

### GN Build Templates
- `ohos_shared_library` - For shared libraries (e.g., `libfms`, `fmskit_native`)
- `ohos_source_set` - For source sets without linking
- `ohos_unittest` - For unit test executables
- `ohos_prebuilt_etc` - For configuration files
- `group` - For grouping targets
- All new build targets must configure sanitize parameters:
  ```gn
  sanitize = {
    cfi = true
    cfi_cross_dso = true
    debug = false
  }
  ```

### Key Directories
- `services/src/` - Form manager service implementation
- `services/include/` - Service header files
- `interfaces/inner_api/` - Internal APIs for inter-process communication
- `interfaces/kits/native/` - Native SDK APIs
- `frameworks/js/napi/` - NAPI bindings for JavaScript
- `frameworks/ets/ani/` - ArkTS Native Interface bindings
- `test/unittest/` - Unit tests
- `test/benchmarktest/` - Performance benchmarks
- `test/fuzztest/` - Fuzz tests

### Common Patterns
- Manager classes: `FormMgr`, `FormProviderMgr`, `FormRefreshMgr`
- Task managers: `FormTaskMgr`, `FormHostTaskMgr`
- Queue classes: `FormQueue`, `FormMgrQueue`
- Connection classes: `FormConnection`, `FormAcquireConnection`
- Observer pattern: `FormObserver`, `FormResourceObserver`

### Memory Management
- Use smart pointers instead of raw pointers
- Use `new (std::nothrow)` for allocations where failure is acceptable
- Follow RAII principles for resource management
- Avoid memory leaks by proper cleanup in destructors
- Do not use try catch to catch C++exceptions

### IPC Communication
- Define interfaces in `interfaces/inner_api/include/`
- Use IDL files in `ipc_idl_gen/` for generating proxy/stub code
- Implement proxy in `*_proxy.cpp`, stub in `*_stub.cpp`
- Use `IREMOTE_OBJECT` and `IRemoteBroker` for IPC base classes

### Developer Checklist
- New interfaces in `form_mgr_interface.h` should not be defined as pure virtual functions
- When IPC message type is `MessageOption::TF_ASYNC`, it's an async message and the peer won't return results; reply cannot get return value. Use `MessageOption::TF_SYNC` when synchronous return is needed
- When adding external dependencies in BUILD.gn, evaluate memory impact
- VM does not support multi-threading operations; all VM-related modifications (vm, runtime, nativeEngine, etc.) must be executed on UI thread
- All UI update operations must be executed on UI thread
- Native and native callback to ArkTS business logic must manage JS objects created during business through scope
- For initialization & one-time operations, prefer using `std::call_once`

