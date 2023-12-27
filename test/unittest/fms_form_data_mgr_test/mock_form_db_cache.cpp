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

#include "form_db_cache.h"

#include <cinttypes>

#include "form_db_info.h"
#include "form_mgr_errors.h"
#include "form_util.h"

namespace {
    int32_t mockCheckAllDBFormMaxSize = 2;
    int32_t mockCheckAllDBFormPreAPPSize = 1;
    int32_t mockCheckType = mockCheckAllDBFormMaxSize;
}

void MockGetAllFormInfo(int32_t mockRet)
{
    mockCheckType = mockRet;
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
    if (mockCheckType == mockCheckAllDBFormMaxSize) {
        for (int formId_index = 0; formId_index < Constants::MAX_FORMS; formId_index++) {
            formDBInfo.providerUserId = formId_index;
            formDBInfos.emplace_back(formDBInfo);
        }
    } else if (mockCheckType == mockCheckAllDBFormPreAPPSize) {
        for (int formId_index = 0; formId_index < Constants::MAX_RECORD_PER_APP; formId_index++) {
            formDBInfo.formUserUids.emplace_back(userUid);
            formDBInfo.providerUserId = FormUtil::GetCurrentAccountId();
            formDBInfos.emplace_back(formDBInfo);
        }
    } else {
        formDBInfos = formDBInfos_;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
