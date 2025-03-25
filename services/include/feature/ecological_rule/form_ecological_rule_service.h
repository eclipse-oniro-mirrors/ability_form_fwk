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

#ifndef FORM_ECOLOGICAL_RULE_PROXY_H
#define FORM_ECOLOGICAL_RULE_PROXY_H

#include <mutex>
#include <singleton.h>
#include "iremote_proxy.h"
#include "form_ecological_rule_interface.h"

namespace OHOS {
namespace AppExecFwk {
using CallerInfo = OHOS::AppExecFwk::FormErmsCallerInfo;
class FormEcologicalRuleClient final : public DelayedRefSingleton<FormEcologicalRuleClient> {
DECLARE_DELAYED_REF_SINGLETON(FormEcologicalRuleClient)
public:
    DISALLOW_COPY_AND_MOVE(FormEcologicalRuleClient);
    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    int32_t IsSupportPublishForm(const std::vector<Want> &wants, const CallerInfo &callerInfo, bool &bSupport);

private:
    static sptr<IFormEcologicalRule> ConnectService();
    static bool CheckConnectService();

    static std::mutex instanceLock_;
    static sptr<IFormEcologicalRule> ecologicalRuleMgrServiceProxy_;
    static sptr<IRemoteObject::DeathRecipient> deathRecipient_;

    static std::string ERMS_ORIGINAL_TARGET;
};

class FormEcologicalRuleDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    FormEcologicalRuleDeathRecipient() {};
    ~FormEcologicalRuleDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;

private:
    DISALLOW_COPY_AND_MOVE(FormEcologicalRuleDeathRecipient);
};

class FormEcologicalRuleProxy : public OHOS::IRemoteProxy<IFormEcologicalRule> {
public:
    using Want = OHOS::AAFwk::Want;

    explicit FormEcologicalRuleProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IFormEcologicalRule>(object)
    {}
    ~FormEcologicalRuleProxy() = default;
    DISALLOW_COPY_AND_MOVE(FormEcologicalRuleProxy);

    int32_t IsSupportPublishForm(const std::vector<Want> &wants, const CallerInfo &callerInfo, bool &bSupport) override;

private:
    static inline BrokerDelegator<FormEcologicalRuleProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FORM_ECOLOGICAL_RULE_PROXY_H
