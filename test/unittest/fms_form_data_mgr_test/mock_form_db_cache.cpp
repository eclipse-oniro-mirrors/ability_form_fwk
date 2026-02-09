/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "data_center/database/form_db_cache.h"

#include <cinttypes>

#include "data_center/database/form_db_info.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"

namespace {
    int32_t g_mockAllDBFormMaxSize = 2;
    int32_t g_mockCheckAllDbFormPreAppSize = 1;
    int32_t g_mockCheckType = g_mockAllDBFormMaxSize;
    int32_t g_mockFormCountsByUserIdRet = 1;
    int32_t g_mockFormCountsByHostBundleNameRet = 1;
    int g_callingUid = 0;
}

void MockGetAllFormInfoSize(int32_t mockRet, int callingUid)
{
    g_mockCheckType = mockRet;
    g_callingUid = callingUid;
}

void MockGetAllFormInfo(int32_t mockRet)
{
    g_mockCheckType = mockRet;
}

void MockGetFormCountsByUserId(int32_t mockRet)
{
    g_mockFormCountsByUserIdRet = mockRet;
}

void MockGetFormCountsByHostBundleName(int32_t mockRet)
{
    g_mockFormCountsByHostBundleNameRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Get all form data from DbCache.
 * @param formDBInfos Storage all DbCache.
 * @return Void.
 */
void FormDbCache::GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos)
{
    FormDBInfo formDBInfo;
    int userUid = -1;
    if (g_mockCheckType == g_mockAllDBFormMaxSize) {
        for (int formId_index = 0; formId_index < Constants::MAX_FORMS; formId_index++) {
            formDBInfo.providerUserId = formId_index;
            formDBInfos.emplace_back(formDBInfo);
        }
    } else if (g_mockCheckType == g_mockCheckAllDbFormPreAppSize) {
        for (int formId_index = 0; formId_index < Constants::MAX_RECORD_PER_HOST; formId_index++) {
            formDBInfo.formUserUids.emplace_back(userUid);
            formDBInfo.providerUserId = FormUtil::GetCurrentAccountId();
            formDBInfos.emplace_back(formDBInfo);
        }
    } else {
        formDBInfos = formDBInfos_;
    }
}

/**
 * @brief Get all form data size.
 * @return int32_t.
 */
int32_t FormDbCache::GetAllFormInfoSize()
{
    if (g_mockCheckType == g_mockAllDBFormMaxSize) {
        return Constants::MAX_FORMS;
    } else if (g_mockCheckType == g_mockCheckAllDbFormPreAppSize && g_callingUid == -1) {
        return Constants::MAX_RECORD_PER_HOST;
    }
    return 0;
}

void FormDbCache::GetLocationMap(std::map<Constants::FormLocation, int> &locationMap)
{
    locationMap[Constants::FormLocation::DESKTOP] = Constants::MAX_RECORD_PER_HOST;
    locationMap[Constants::FormLocation::SCREEN_LOCK] = 1;
}

int32_t FormDbCache::GetFormCountsByUserId(const int32_t userId)
{
    return g_mockFormCountsByUserIdRet;
}

int32_t FormDbCache::GetFormCountsByHostBundleName(const std::string &hostBundleName)
{
    return g_mockFormCountsByHostBundleNameRet;
}
} // namespace AppExecFwk
} // namespace OHOS
