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

#ifndef OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H
#define OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H

#include <vector>

#include "erms_mgr_interface.h"
#include "gmock/gmock.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using OHOS::AppExecFwk::ErmsParams::CallerInfo;
using OHOS::AppExecFwk::ErmsParams::ExperienceRule;

class MockEcologicalRuleMgrService : public IRemoteStub<IEcologicalRuleManager> {
public:
    MOCK_METHOD3(QueryFreeInstallExperience, int32_t(const Want &want,
        const CallerInfo &callerInfo, ExperienceRule &rule));
    MOCK_METHOD5(EvaluateResolveInfos, int32_t(const Want &want, const CallerInfo &callerInfo,
        int32_t type, std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> extensionInfos));
    MOCK_METHOD3(QueryStartExperience, int32_t(const Want &want, const CallerInfo &callerInfo, ExperienceRule &rule));
    MOCK_METHOD2(QueryPublishFormExperience, int32_t(const Want &want, ExperienceRule &rule));
    MOCK_METHOD3(IsSupportPublishForm, int32_t(const Want &want, const CallerInfo &callerInfo, ExperienceRule &rule));
    MOCK_METHOD0(QueryLastSyncTime, long());
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_MOCK_ECOLOGICAL_RULE_MANAGER_H
