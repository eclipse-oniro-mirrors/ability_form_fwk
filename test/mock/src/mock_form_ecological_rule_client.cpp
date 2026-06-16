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

#include "mock_form_ecological_rule_client.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/ecological_rule/form_ecological_rule_service.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormEcologicalRuleClient> MockFormEcologicalRuleClient::obj = nullptr;

FormEcologicalRuleClient::FormEcologicalRuleClient() {}
FormEcologicalRuleClient::~FormEcologicalRuleClient() {}

int32_t FormEcologicalRuleProxy::IsSupportPublishForm(const std::vector<Want> &wants,
    const CallerInfo &callerInfo, bool &bSupport)
{
    bSupport = true;
    return ERR_OK;
}

int32_t FormEcologicalRuleClient::IsSupportPublishForm(const std::vector<Want> &wants,
    const FormErmsCallerInfo &callerInfo, bool &bSupport)
{
    GTEST_LOG_(INFO) << "IsSupportPublishForm called";
    if (AppExecFwk::MockFormEcologicalRuleClient::obj) {
        return AppExecFwk::MockFormEcologicalRuleClient::obj->IsSupportPublishForm(wants, callerInfo, bSupport);
    }
    bSupport = true;
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
