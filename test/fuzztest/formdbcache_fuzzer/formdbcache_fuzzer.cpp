/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formdbcache_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/database/form_db_cache.h"
#include "data_center/database/form_db_info.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t INDEX_MAX = 5;
const nlohmann::json JSON_FORMS = R"({})"_json;

void GenerateMapData(FuzzedDataProvider *fdp, std::set<int64_t> &matchedFormIds,
    std::map<FormIdKey, std::set<int64_t>> &noHostDBFormsMap, std::map<int64_t, bool> &foundFormsMap)
{
    int32_t index = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    for (int32_t i = 0; i < index; i++) {
        int64_t formId = fdp->ConsumeIntegral<int64_t>();
        matchedFormIds.insert(formId);
        std::string bundleName = fdp->ConsumeRandomLengthString();
        std::string abilityName = fdp->ConsumeRandomLengthString();
        FormIdKey formIdKey(bundleName, abilityName);
        std::set<int64_t> formIds = {};
        int32_t indexj = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
        for (int32_t j = 0; j < indexj; j++) {
            int64_t dbFormId = fdp->ConsumeIntegral<int64_t>();
            formIds.insert(dbFormId);
        }
        noHostDBFormsMap[formIdKey] = formIds;
        int64_t foundFormId = fdp->ConsumeIntegral<int64_t>();
        bool isFound = fdp->ConsumeBool();
        foundFormsMap[foundFormId] = isFound;
    }
}

void GenerateFormDBInfo(FuzzedDataProvider *fdp, FormDBInfo &info)
{
    std::vector<Constants::FormLocation> formLocations = {Constants::FormLocation::OTHER,
        Constants::FormLocation::DESKTOP, Constants::FormLocation::FORM_CENTER,
        Constants::FormLocation::FORM_MANAGER, Constants::FormLocation::NEGATIVE_SCREEN,
        Constants::FormLocation::FORM_CENTER_NEGATIVE_SCREEN,
        Constants::FormLocation::FORM_MANAGER_NEGATIVE_SCREEN,
        Constants::FormLocation::SCREEN_LOCK, Constants::FormLocation::AI_SUGGESTION};
    info.formId = fdp->ConsumeIntegral<int64_t>();
    info.userId = fdp->ConsumeIntegral<int32_t>();
    info.providerUserId = fdp->ConsumeIntegral<int32_t>();
    info.formName = fdp->ConsumeRandomLengthString();
    info.bundleName = fdp->ConsumeRandomLengthString();
    info.moduleName = fdp->ConsumeRandomLengthString();
    info.abilityName = fdp->ConsumeRandomLengthString();
    info.formUserUids = {};
    info.formLocation = formLocations[fdp->ConsumeIntegralInRange<size_t>(0, formLocations.size() - 1)];
    info.isThemeForm = fdp->ConsumeBool();
    info.enableForm = fdp->ConsumeBool();
    info.lockForm = fdp->ConsumeBool();
    int32_t indexj = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    for (int32_t j = 0; j < indexj; j++) {
        int formUserUid = fdp->ConsumeIntegral<int>();
        info.formUserUids.push_back(formUserUid);
    }
}

std::vector<FormDBInfo> GetFormDBInfos(FuzzedDataProvider *fdp)
{
    std::vector<FormDBInfo> formDBInfos = {};
    int32_t index = fdp->ConsumeIntegralInRange(0, INDEX_MAX);
    for (int32_t i = 0; i < index; i++) {
        FormDBInfo info;
        OHOS::GenerateFormDBInfo(fdp, info);
        formDBInfos.push_back(info);
    }
    return formDBInfos;
}

void InnerFormInfoTest(FuzzedDataProvider *fdp)
{
    InnerFormInfo innerFormInfo;
    FormDBInfo formDBInfo;
    OHOS::GenerateFormDBInfo(fdp, formDBInfo);
    innerFormInfo.formDBInfo_ = formDBInfo;
    int callingUid = fdp->ConsumeIntegral<int>();
    nlohmann::json jsonObject = JSON_FORMS;
    innerFormInfo.ToJson(jsonObject);
    innerFormInfo.AddUserUid(callingUid);
    innerFormInfo.DeleteUserUid(callingUid);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    OHOS::InnerFormInfoTest(fdp);
    FormDbCache formDbCache;
    formDbCache.formDBInfos_ = OHOS::GetFormDBInfos(fdp);
    formDbCache.Start();
    FormDBInfo formDBInfo;
    formDbCache.SaveFormInfo(formDBInfo);
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    formDbCache.DeleteFormInfo(formId);
    int32_t hostUid = fdp->ConsumeIntegral<int32_t>();
    formDbCache.IsHostOwner(formId, hostUid);
    std::string bundleName = fdp->ConsumeRandomLengthString();
    std::string moduleName = fdp->ConsumeRandomLengthString();
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    int32_t callingUid = fdp->ConsumeIntegral<int32_t>();
    uint32_t versionCode = fdp->ConsumeIntegral<uint32_t>();
    std::vector<FormDBInfo> removedDBForms;
    std::vector<FormDBInfo> formDBInfos;
    formDbCache.GetAllFormDBInfoByBundleName(bundleName, userId, formDBInfos);
    removedDBForms.emplace_back(formDBInfo);
    formDbCache.DeleteFormInfoByBundleName(bundleName, userId, removedDBForms);
    formDbCache.GetAllFormInfo(formDBInfos);
    std::map<Constants::FormLocation, int> locationMap;
    formDbCache.GetLocationMap(locationMap);
    FormRecord record;
    formDbCache.GetDBRecord(formId, record);
    formDbCache.GetMatchCount(bundleName, moduleName);
    std::set<int64_t> matchedFormIds = {};
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap = {};
    std::map<int64_t, bool> foundFormsMap = {};
    OHOS::GenerateMapData(fdp, matchedFormIds, noHostDBFormsMap, foundFormsMap);
    formDbCache.BatchDeleteNoHostDBForms(callingUid, noHostDBFormsMap, foundFormsMap);
    formDbCache.GetMultiAppFormVersionCode(bundleName);
    formDbCache.UpdateMultiAppFormVersionCode(bundleName, versionCode);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}