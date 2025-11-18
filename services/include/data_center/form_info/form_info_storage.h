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

#ifndef OHOS_FORM_FWK_FORM_INFO_STORAGE_H
#define OHOS_FORM_FWK_FORM_INFO_STORAGE_H

#include "form_info.h"
#include "form_info_filter.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AAFwk {
struct FormInfoStorage {
    int32_t userId = -1;
    std::vector<AppExecFwk::FormInfo> formInfos;

    FormInfoStorage() = default;
    FormInfoStorage(int32_t userId, const std::vector<AppExecFwk::FormInfo> &formInfos);
    ~FormInfoStorage() = default;

    void GetAllFormsInfo(int32_t userId, std::vector<AppExecFwk::FormInfo> &formInfos) const;
    void GetFormsInfoByModule(int32_t userId, const std::string &moduleName,
        std::vector<AppExecFwk::FormInfo> &formInfos) const;
    void GetFormsInfoByFilter(int32_t userId,
        const AppExecFwk::FormInfoFilter &filter, std::vector<AppExecFwk::FormInfo> &formInfos) const;
private:
    bool IsGameCard(const AppExecFwk::FormInfo &formInfo) const;
    bool IsFunInterFormInfoFiltered(const AppExecFwk::FormInfo &formInfo) const;
    bool IsEquipmentLevelFiltered(const AppExecFwk::FormInfo &formInfo) const;
};

void to_json(nlohmann::json &jsonObject, const FormInfoStorage &formInfoStorage);
void from_json(const nlohmann::json &jsonObject, FormInfoStorage &formInfoStorage);
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_INFO_STORAGE_H
