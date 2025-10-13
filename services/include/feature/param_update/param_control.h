/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_PARAM_CONTROL_H
#define OHOS_FORM_FWK_PARAM_CONTROL_H

#include <singleton.h>
#include <string>
#include "nlohmann/json.hpp"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {

struct ParamCtrl {
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string formName;
    std::vector<int32_t> dimensions;
    uint32_t appVersionStart;
    uint32_t appVersionEnd;
    int32_t updateDuration;
    std::string policy;
};

void from_json(const nlohmann::json &jsonObject, ParamCtrl &paramCtrl);

class ParamControl final : public DelayedRefSingleton<ParamControl> {
    DECLARE_DELAYED_REF_SINGLETON(ParamControl);
public:
    DISALLOW_COPY_AND_MOVE(ParamControl);

    void DealDueParam(const std::string &jsonStr);
    int32_t GetDueUpdateDuration(const FormRecord &formRecord);
    bool IsFormDisable(const FormRecord &formRecord);
    bool IsFormRemove(const FormRecord &formRecord);
    void ReloadDueControlByAppUpgrade(const std::vector<FormRecord> &formRecords);
private:
    void ParamTransfer();
    void ParseJsonToObj(const nlohmann::json &jsonObject);
    bool IsParamValid(ParamCtrl &paramCtrl, bool isDisableCtrl);
    bool IsFormInfoMatch(const FormRecord &formRecord, const ParamCtrl &paramCtrl, const bool isNewVersion = true);
    bool IsSameUpdateDuration(const FormRecord &formRecord,
        const ParamCtrl &paramCtrl, const std::vector<ParamCtrl> &compareCtrls);
    bool IsSamePolicy(const FormRecord &formRecord,
        const ParamCtrl &paramCtrl, const std::vector<ParamCtrl> &compareCtrls);
    void ExecUpdateDurationCtrl(const bool isApply, const std::vector<ParamCtrl> &paramCtrls,
        const bool isAppUpgrade = false);
    void ExecDisableCtrl(const bool isApply, const std::vector<ParamCtrl> &paramCtrls,
        const bool isAppUpgrade = false);

    std::vector<ParamCtrl> preUpdateDurationCtrl_;
    std::vector<ParamCtrl> preDisableCtrl_;

    std::vector<ParamCtrl> nextUpdateDurationCtrl_;
    std::vector<ParamCtrl> nextDisableCtrl_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_PARAM_CONTROL_H