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

#include "formcommonadaptertwo_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "rdb_helper.h"
#include "ffrt.h"

#define private public
#define protected public
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_info.h"
#include "form_major_info.h"
#include "want.h"

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

// Interpose RdbHelper::GetRdbStore so no real rdb store is opened. Opening the
// store spawns async rdb threads that outlive the fuzz process and race with
// rdb's static SqlLog teardown at exit (heap-use-after-free).
namespace OHOS {
namespace NativeRdb {
std::shared_ptr<RdbStore> RdbHelper::GetRdbStore(
    const RdbStoreConfig &config, int version, RdbOpenCallback &openCallback, int &errCode)
{
    errCode = E_ERROR;
    return nullptr;
}
} // namespace NativeRdb
} // namespace OHOS

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_UPDATE_DURATION = 3600;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_VERSION_CODE = 1000;
constexpr int32_t MIN_VERSION_CODE = 1;
constexpr int32_t MAX_COMPATIBLE_VERSION = 100;
constexpr int32_t MIN_COMPATIBLE_VERSION = 1;
constexpr int32_t MAX_FORM_TYPE = 2;
constexpr int32_t MAX_PRIVACY_LEVEL = 3;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_FORM_LOCATION_TYPE = 5;
constexpr int32_t MAX_STRING_LENGTH_16 = 16;
constexpr int32_t MAX_STRING_LENGTH_32 = 32;
constexpr int32_t MAX_STRING_LENGTH_64 = 64;
constexpr int32_t MAX_STRING_LENGTH_256 = 256;
constexpr int32_t MAX_BUNDLE_TYPE = 2;
constexpr int32_t MAX_RENDERING_MODE = 2;

std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safeResult;
    for (char c : result) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-' ||
            c == '.' || c == '/' || c == ':') {
            safeResult += c;
        } else {
            safeResult += '_';
        }
    }
    return safeResult.empty() ? "default" : safeResult;
}

FormItemInfo GenerateFormItemInfo(FuzzedDataProvider *fdp)
{
    FormItemInfo itemInfo;
    itemInfo.SetFormId(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));

    itemInfo.SetPackageName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetProviderBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetHostBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetAbilityName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetFormName(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetSpecificationId(fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID));
    itemInfo.SetEnableUpdateFlag(fdp->ConsumeBool());
    itemInfo.SetUpdateDuration(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_UPDATE_DURATION));

    itemInfo.SetScheduledUpdateTime(GenerateSafeString(fdp, MAX_STRING_LENGTH_16));

    itemInfo.SetTemporaryFlag(fdp->ConsumeBool());
    itemInfo.SetFormVisibleNotify(fdp->ConsumeBool());

    itemInfo.SetFormSrc(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetVersionCode(fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE));

    itemInfo.SetVersionName(GenerateSafeString(fdp, MAX_STRING_LENGTH_32));

    itemInfo.SetCompatibleVersion(fdp->ConsumeIntegralInRange<uint32_t>(MIN_COMPATIBLE_VERSION,
        MAX_COMPATIBLE_VERSION));
    itemInfo.SetType(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    itemInfo.SetUiSyntax(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    itemInfo.SetIsDynamic(fdp->ConsumeBool());
    itemInfo.SetTransparencyEnabled(fdp->ConsumeBool());
    itemInfo.SetPrivacyLevel(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL));

    itemInfo.SetJsComponentName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetAbilityModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetDeviceId(GenerateSafeString(fdp, MAX_STRING_LENGTH_64));

    itemInfo.SetDataProxyFlag(fdp->ConsumeBool());
    itemInfo.SetSystemAppFlag(fdp->ConsumeBool());
    itemInfo.SetProviderUid(fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID));

    itemInfo.SetDescription(GenerateSafeString(fdp, MAX_STRING_LENGTH_256));

    itemInfo.SetFormLocation(static_cast<OHOS::AppExecFwk::Constants::FormLocation>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION)));
    itemInfo.SetIsThemeForm(fdp->ConsumeBool());
    itemInfo.SetFormBundleType(static_cast<BundleType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_BUNDLE_TYPE)));
    itemInfo.SetEnableForm(fdp->ConsumeBool());
    itemInfo.SetRenderingMode(static_cast<OHOS::AppExecFwk::Constants::RenderingMode>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_RENDERING_MODE)));
    itemInfo.SetLockForm(fdp->ConsumeBool());
    itemInfo.SetProtectForm(fdp->ConsumeBool());
    itemInfo.SetDataProxyIgnoreFormVisibility(fdp->ConsumeBool());
    itemInfo.SetDistributedForm(fdp->ConsumeBool());

    itemInfo.SetUiModuleName(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetIsTemplateForm(fdp->ConsumeBool());

    itemInfo.SetTemplateFormImperativeFwk(GenerateSafeString(fdp, MAX_STRING_LENGTH_64));

    return itemInfo;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormCommonAdapter::GetInstance();

    // Fuzz AlignCloneProviderUid: first call with fully fuzzed FormItemInfo.
    // FormBmsHelper::GetEnabledCloneIndex will fail in fuzz env, hitting the
    // error-return branch; diverse providerBundleName values still exercise
    // string handling paths.
    FormItemInfo formItemInfo1 = GenerateFormItemInfo(fdp);
    adapter.AlignCloneProviderUid(formItemInfo1);

    // Fuzz AlignCloneProviderUid: second call with different fuzzed input to
    // exercise branch diversity across invocations.
    FormItemInfo formItemInfo2 = GenerateFormItemInfo(fdp);
    adapter.AlignCloneProviderUid(formItemInfo2);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
