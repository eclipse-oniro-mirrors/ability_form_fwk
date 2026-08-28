/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_FRAME_HANDLER_H
#define OHOS_FORM_FWK_FORM_FRAME_HANDLER_H

#include "form_cross_device_constants.h"
#include <cstdint>
#include <string>

namespace OHOS {
namespace AppExecFwk {

// FormConnectionPool dispatches incoming frames to IFrameHandler; FormPublishRouter implements it.
class IFrameHandler {
public:
    virtual ~IFrameHandler() = default;
    virtual void OnFrame(int32_t fd, FormCdMsgType msgType,
        uint32_t seqId, const std::string &payload) = 0;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_FRAME_HANDLER_H
