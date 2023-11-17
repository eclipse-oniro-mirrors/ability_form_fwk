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

#ifndef OHOS_FORM_FWK_FORM_HOST_DELEGATE_INTERFACE_H
#define OHOS_FORM_FWK_FORM_HOST_DELEGATE_INTERFACE_H

#include <string>
#include "form_instance.h"
#include "iremote_broker.h"
#include "running_form_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
class IFormHostDelegate : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IFormHostDelegate");

    /**
     * @brief The form router event.
     * @param want The want to start ability, this value is same with the fms router event.
     */
    virtual int32_t RouterEvent(const int64_t formId, const Want &want) = 0;

    enum class Message {
        // ipc id for form router proxy (4002)
        FORM_ROUTER_PROXY_MGR = 4002,
    };
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_HOST_DELEGATE_INTERFACE_H