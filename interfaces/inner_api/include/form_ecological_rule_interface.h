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

#ifndef FORM_ECOLOGICAL_RULE_INTERFACE_H
#define FORM_ECOLOGICAL_RULE_INTERFACE_H

#include <string>
#include "iremote_broker.h"
#include "form_ecological_rule_param.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class IFormEcologicalRule : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.cloud.ecologicalrulemgrservice.IFormEcologicalRule");

    using Want = OHOS::AAFwk::Want;

    using CallerInfo = OHOS::AppExecFwk::FormErmsCallerInfo;

    virtual int32_t IsSupportPublishForm(const std::vector<Want> &wants, const CallerInfo &callerInfo,
        bool &bSupport) = 0;

    enum {
        IS_SUPPORT_PUBLISH_FORM_CMD = 3
    };

    enum ErrCode {
        ERR_BASE = (-99),
        ERR_FAILED = (-1),
        ERR_PERMISSION_DENIED = (-2),
        ERR_OK = 0,
    };
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FORM_ECOLOGICAL_RULE_INTERFACE_H