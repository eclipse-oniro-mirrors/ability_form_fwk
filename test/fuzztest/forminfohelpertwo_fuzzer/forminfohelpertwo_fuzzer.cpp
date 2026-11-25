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

#include "forminfohelpertwo_fuzzer.h"

#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/bundle_form_info.h"
#undef private
#undef protected

#include "bundle_mgr_client.h"
#include "form_info.h"
#include "form_constants.h"
#include "ffrt.h"
#include "rdb_helper.h"

extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
}

// The stub allocator does not return storage inside a real ffrt task, so
// ffrt_submit_base must be stubbed as well to avoid heap corruption.
extern "C" void ffrt_submit_base(ffrt_function_header_t* f, const ffrt_deps_t* inDeps,
    const ffrt_deps_t* outDeps, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
}

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

// Interpose GetRdbStore to avoid opening a real store whose async threads
// outlive the fuzzer and race with rdb's static teardown at exit.
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

namespace OHOS {

constexpr int32_t MAX_STR_LEN = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t NUM_SCENARIOS = 5;

// --- Helpers ---
static std::string GenerateSafeString(FuzzedDataProvider *fdp)
{
    std::string s = fdp->ConsumeRandomLengthString(MAX_STR_LEN);
    return s.empty() ? "default" : s;
}

static BundleInfo GenerateBundleInfo(FuzzedDataProvider *fdp)
{
    BundleInfo bundleInfo;
    bundleInfo.name = GenerateSafeString(fdp);
    bundleInfo.appId = GenerateSafeString(fdp);
    bundleInfo.versionCode = fdp->ConsumeIntegral<int32_t>();
    bundleInfo.applicationInfo.isSystemApp = fdp->ConsumeBool();
    return bundleInfo;
}

static FormInfo GenerateFormInfo(FuzzedDataProvider *fdp)
{
    FormInfo formInfo;
    formInfo.name = GenerateSafeString(fdp);
    formInfo.bundleName = GenerateSafeString(fdp);
    formInfo.moduleName = GenerateSafeString(fdp);
    formInfo.abilityName = GenerateSafeString(fdp);
    formInfo.descriptionId = fdp->ConsumeIntegral<int32_t>();
    formInfo.displayName = GenerateSafeString(fdp);
    return formInfo;
}

static ExtensionAbilityInfo GenerateExtensionInfo(FuzzedDataProvider *fdp)
{
    ExtensionAbilityInfo extensionInfo;
    extensionInfo.bundleName = GenerateSafeString(fdp);
    extensionInfo.moduleName = GenerateSafeString(fdp);
    extensionInfo.name = GenerateSafeString(fdp);
    extensionInfo.description = GenerateSafeString(fdp);
    extensionInfo.type = ExtensionAbilityType::FORM;
    return extensionInfo;
}

// ===================================================================
// Scenario A: LoadFormConfigInfoByBundleNames (public, L82-127)
// Covers: empty bundleNames -> INVALID_PARAM (L86-88);
//   non-empty -> BatchGetBundleInfo fails in fuzz env -> GET_BUNDLE_FAILED (L92-98).
// ===================================================================
static void ScenarioA(FuzzedDataProvider *fdp)
{
    int32_t userId = fdp->ConsumeIntegral<int32_t>();

    // Call 1: empty bundleNames -> early INVALID_PARAM
    {
        std::vector<std::string> emptyNames;
        std::unordered_map<std::string, std::vector<FormInfo>> formInfosMap;
        FormInfoHelper::LoadFormConfigInfoByBundleNames(emptyNames, userId, formInfosMap);
    }

    // Call 2: non-empty bundleNames -> BatchGetBundleInfo fails -> GET_BUNDLE_FAILED
    {
        std::vector<std::string> bundleNames;
        int32_t count = fdp->ConsumeIntegralInRange<int32_t>(1, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < count; i++) {
            bundleNames.push_back(GenerateSafeString(fdp));
        }
        std::unordered_map<std::string, std::vector<FormInfo>> formInfosMap;
        FormInfoHelper::LoadFormConfigInfoByBundleNames(bundleNames, userId, formInfosMap);
    }
}

// ===================================================================
// Scenario B: ResolveEnableTint (public, L129-138) + IsAccountMetadataEnabled (private, L352-364)
// ResolveEnableTint covers: isSystemApp=true + enableTint=BOOL_UNSPECIFIED -> BOOL_TRUE (L131-134);
//   isSystemApp=true + enableTint already BOOL_TRUE -> no change (L132 false);
//   isSystemApp=false -> BOOL_FALSE (L135-137).
// IsAccountMetadataEnabled covers: !isSystemApp -> false (L355-357);
//   isSystemApp + matching customizeData -> true (L358-362);
//   isSystemApp + no match -> false (L363).
// ===================================================================
static void ScenarioB(FuzzedDataProvider *fdp)
{
    // --- ResolveEnableTint branches ---
    // Branch 1: isSystemApp=true + enableTint=BOOL_UNSPECIFIED -> BOOL_TRUE
    {
        FormInfo formInfo = GenerateFormInfo(fdp);
        formInfo.enableTint = BoolEnum::BOOL_UNSPECIFIED;
        FormInfoHelper::ResolveEnableTint(formInfo, true);
    }
    // Branch 2: isSystemApp=true + enableTint=BOOL_TRUE (already set) -> no change
    {
        FormInfo formInfo = GenerateFormInfo(fdp);
        formInfo.enableTint = BoolEnum::BOOL_TRUE;
        FormInfoHelper::ResolveEnableTint(formInfo, true);
    }
    // Branch 3: isSystemApp=false -> BOOL_FALSE
    {
        FormInfo formInfo = GenerateFormInfo(fdp);
        formInfo.enableTint = BoolEnum::BOOL_UNSPECIFIED;
        FormInfoHelper::ResolveEnableTint(formInfo, false);
    }

    // --- IsAccountMetadataEnabled branches ---
    // Branch 1: !isSystemApp -> false
    {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.isSystemApp = false;
        std::vector<FormCustomizeData> customizeDatas;
        FormInfoHelper::IsAccountMetadataEnabled(bundleInfo, customizeDatas);
    }
    // Branch 2: isSystemApp + matching METADATA_ACCOUNT_REFRESH/TRUE -> true
    {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.isSystemApp = true;
        FormCustomizeData data;
        data.name = Constants::METADATA_ACCOUNT_REFRESH;
        data.value = Constants::METADATA_ACCOUNT_VALUE_TRUE;
        std::vector<FormCustomizeData> customizeDatas;
        customizeDatas.push_back(data);
        FormInfoHelper::IsAccountMetadataEnabled(bundleInfo, customizeDatas);
    }
    // Branch 3: isSystemApp + no matching customizeData -> false
    {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.isSystemApp = true;
        FormCustomizeData data;
        data.name = GenerateSafeString(fdp);
        data.value = GenerateSafeString(fdp);
        std::vector<FormCustomizeData> customizeDatas;
        customizeDatas.push_back(data);
        FormInfoHelper::IsAccountMetadataEnabled(bundleInfo, customizeDatas);
    }
    // Branch 4: isSystemApp + empty customizeDatas -> false
    {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.isSystemApp = true;
        std::vector<FormCustomizeData> customizeDatas;
        FormInfoHelper::IsAccountMetadataEnabled(bundleInfo, customizeDatas);
    }
}

// ===================================================================
// Scenario C: LoadAbilityFormConfigInfo (private, L391-407) + LoadFormsForExtension (private, L284-318)
// LoadAbilityFormConfigInfo covers: empty hapModuleInfos -> empty loop;
//   non-empty hapModuleInfos -> FormBmsHelper::GetFormsInfoByModule fails -> continue.
// LoadFormsForExtension covers: hasDistributedForm=false path (default) -> GetResMgr -> GetProfilesByResMgr
//   -> metaData+templateMetaData both true -> early return (L311-314);
//   hasDistributedForm=true path -> client->GetProfileFromSharedHap fails -> return (L297-300).
// ===================================================================
static void ScenarioC(FuzzedDataProvider *fdp)
{
    // --- LoadAbilityFormConfigInfo: empty hapModuleInfos ---
    {
        BundleInfo bundleInfo = GenerateBundleInfo(fdp);
        std::vector<FormInfo> formInfos;
        FormInfoHelper::LoadAbilityFormConfigInfo(bundleInfo, formInfos);
    }

    // --- LoadAbilityFormConfigInfo: non-empty hapModuleInfos ---
    {
        BundleInfo bundleInfo = GenerateBundleInfo(fdp);
        HapModuleInfo moduleInfo;
        moduleInfo.moduleName = GenerateSafeString(fdp);
        bundleInfo.hapModuleInfos.push_back(moduleInfo);
        std::vector<FormInfo> formInfos;
        FormInfoHelper::LoadAbilityFormConfigInfo(bundleInfo, formInfos);
    }

    // --- LoadFormsForExtension: hasDistributedForm=false (no ENTRY module) ---
    {
        auto client = DelayedSingleton<BundleMgrClient>::GetInstance();
        if (client == nullptr) {
            return;
        }
        BundleInfo bundleInfo = GenerateBundleInfo(fdp);
        ExtensionAbilityInfo extensionInfo = GenerateExtensionInfo(fdp);
        int32_t userId = fdp->ConsumeIntegral<int32_t>();
        std::vector<FormInfo> formInfos;
        std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> resMgrCache;
        FormInfoHelper::LoadFormsForExtension(client, bundleInfo, extensionInfo, userId, formInfos, resMgrCache);
    }

    // --- LoadFormsForExtension: hasDistributedForm=true (ENTRY module + formWidgetModule, size<2) ---
    {
        auto client = DelayedSingleton<BundleMgrClient>::GetInstance();
        if (client == nullptr) {
            return;
        }
        BundleInfo bundleInfo = GenerateBundleInfo(fdp);
        HapModuleInfo entryModule;
        entryModule.moduleType = ModuleType::ENTRY;
        entryModule.formWidgetModule = GenerateSafeString(fdp);
        bundleInfo.hapModuleInfos.push_back(entryModule);
        ExtensionAbilityInfo extensionInfo = GenerateExtensionInfo(fdp);
        int32_t userId = fdp->ConsumeIntegral<int32_t>();
        std::vector<FormInfo> formInfos;
        std::unordered_map<std::string, std::shared_ptr<Global::Resource::ResourceManager>> resMgrCache;
        FormInfoHelper::LoadFormsForExtension(client, bundleInfo, extensionInfo, userId, formInfos, resMgrCache);
    }
}

// ===================================================================
// Scenario D: GetCompressedProfile (private, L206-224) + GetRawFileProfile (private, L226-252)
// Both dereference resMgr directly (no null guard), so a valid (non-null) ResourceManager
// is obtained via GetResourceManager. With an empty ResourceManager, GetProfileDataByName
// and GetProfileByName return != SUCCESS -> false branch.
// ===================================================================
static void ScenarioD(FuzzedDataProvider *fdp)
{
    BundleInfo bundleInfo = GenerateBundleInfo(fdp);
    auto resMgr = FormInfoHelper::GetResourceManager(bundleInfo);
    if (resMgr == nullptr) {
        return;
    }

    std::string profileName = GenerateSafeString(fdp);
    std::string profile;

    // GetCompressedProfile: GetProfileDataByName fails -> false
    FormInfoHelper::GetCompressedProfile(resMgr, profileName, profile);

    // GetRawFileProfile: GetProfileByName fails -> false
    FormInfoHelper::GetRawFileProfile(resMgr, profileName, profile);
}

// ===================================================================
// Scenario E: LoadFormConfigInfoByBundleNames with fuzz-derived bundle sets +
//   ResolveEnableTint edge cases. Supplements A/B with wider input variety.
// ===================================================================
static void ScenarioE(FuzzedDataProvider *fdp)
{
    int32_t userId = fdp->ConsumeIntegral<int32_t>();

    // Single-bundle LoadFormConfigInfoByBundleNames
    {
        std::vector<std::string> bundleNames = { GenerateSafeString(fdp) };
        std::unordered_map<std::string, std::vector<FormInfo>> formInfosMap;
        FormInfoHelper::LoadFormConfigInfoByBundleNames(bundleNames, userId, formInfosMap);
    }

    // ResolveEnableTint with fuzz-derived isSystemApp and enableTint
    {
        FormInfo formInfo = GenerateFormInfo(fdp);
        bool isSystemApp = fdp->ConsumeBool();
        // Cycle through all BoolEnum values for branch coverage
        formInfo.enableTint = BoolEnum::BOOL_UNSPECIFIED;
        FormInfoHelper::ResolveEnableTint(formInfo, isSystemApp);
        formInfo.enableTint = BoolEnum::BOOL_TRUE;
        FormInfoHelper::ResolveEnableTint(formInfo, isSystemApp);
        formInfo.enableTint = BoolEnum::BOOL_FALSE;
        FormInfoHelper::ResolveEnableTint(formInfo, isSystemApp);
    }

    // IsAccountMetadataEnabled with fuzz-derived customizeDatas
    {
        BundleInfo bundleInfo;
        bundleInfo.applicationInfo.isSystemApp = fdp->ConsumeBool();
        std::vector<FormCustomizeData> customizeDatas;
        int32_t count = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        for (int32_t i = 0; i < count; i++) {
            FormCustomizeData data;
            data.name = GenerateSafeString(fdp);
            data.value = GenerateSafeString(fdp);
            customizeDatas.push_back(data);
        }
        FormInfoHelper::IsAccountMetadataEnabled(bundleInfo, customizeDatas);
    }
}

static bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t scenario = fdp->ConsumeIntegral<uint8_t>();
    switch (scenario % NUM_SCENARIOS) {
        case 0:
            ScenarioA(fdp);
            break;
        case 1:
            ScenarioB(fdp);
            break;
        case 2:
            ScenarioC(fdp);
            break;
        case 3:
            ScenarioD(fdp);
            break;
        case 4:
            ScenarioE(fdp);
            break;
        default:
            break;
    }
    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
