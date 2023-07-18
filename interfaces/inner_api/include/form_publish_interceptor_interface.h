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

#ifndef OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_INTERFACE_H
#define OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_INTERFACE_H

#include "iremote_broker.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;

/**
 * @class IFormPublishInterceptor
 * IFormPublishInterceptor interface is used to declare the interceptor for publish form
 * when the system handler is not found.
 */
class IFormPublishInterceptor : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormPublishInterceptor")

    /**
     * @brief Process the publish form request when the system handler is not found.
     * @param want Indicates the {@link Want} structure containing form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t ProcessPublishForm(const Want &want)
    {
        return 0;
    }

    enum class Message {
        // ipc id 1-1000 for kit
        // ipc id 1001-2000 for DMS
        // ipc id 2001-3000 for tools
        FORM_PROCESS_PUBLISH_FORM = 3301,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_PUBLISH_INTERCEPTOR_INTERFACE_H
