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

#ifndef OHOS_FORM_FWK_FORM_CROSS_DEVICE_CODEC_H
#define OHOS_FORM_FWK_FORM_CROSS_DEVICE_CODEC_H

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "form_cross_device_constants.h"
#include "form_cross_device_request.h"

namespace OHOS {
namespace AppExecFwk {
// Frame: magic(4,BE) + version(1) + msgType(1) + reserved(2) + seqId(4,BE) + payloadLen(4,BE) + payload
// Dirty frames (bad magic/version/payloadLen) drop the fd buffer.
class FormCrossDeviceCodec {
public:
    using FrameHandler = std::function<void(FormCdMsgType msgType, uint32_t seqId, const std::string &payload)>;

    static bool EncodeRequest(FormCdMsgType msgType, uint32_t seqId,
        const FormCrossDeviceRequest &req, std::string &out);
    static bool EncodeResult(FormCdMsgType msgType, uint32_t seqId,
        const PublishFormCrossDeviceResult &res, std::string &out);
    static bool BuildRawFrame(FormCdMsgType msgType, uint32_t seqId,
        const std::string &payload, std::string &out);
    void Feed(int32_t fd, const void *data, uint32_t len, const FrameHandler &onFrame);
    static bool DecodeRequest(const std::string &payload, FormCrossDeviceRequest &req);
    static bool DecodeResult(const std::string &payload, PublishFormCrossDeviceResult &res);
    void Clear(int32_t fd);

private:
    std::mutex mutex_;
    std::map<int32_t, std::string> fragMap_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CROSS_DEVICE_CODEC_H
