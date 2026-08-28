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

#ifndef OHOS_FORM_FWK_FORM_CROSS_DEVICE_CONSTANTS_H
#define OHOS_FORM_FWK_FORM_CROSS_DEVICE_CONSTANTS_H

#include <cstdint>

namespace OHOS {
namespace AppExecFwk {
constexpr uint32_t FORM_CD_MAGIC = 0x464F5243;
constexpr uint8_t FORM_CD_PROTO_VERSION = 1;
constexpr uint32_t FORM_CD_FRAME_HEADER_SIZE = 16;
constexpr uint32_t FORM_CD_MAX_PAYLOAD = 256 * 1024;

// Wire protocol message types (uint8_t range partition):
//   REQUEST_BASE(1-9)  Request   (initiated by caller, expects Response)
//   RESPONSE_BASE(10-19) Response (reply to a Request, same seqId)
//   NOTIFY_BASE(20-29)  Notify   (unsolicited, no seqId correlation)
constexpr uint8_t FORM_CD_MSG_REQUEST_BASE  = 1;
constexpr uint8_t FORM_CD_MSG_RESPONSE_BASE = 10;
constexpr uint8_t FORM_CD_MSG_NOTIFY_BASE   = 20;

enum class FormCdMsgType : uint8_t {
    REQUEST_PUBLISH     = FORM_CD_MSG_REQUEST_BASE,
    RESPONSE_PUBLISH    = FORM_CD_MSG_RESPONSE_BASE,
    ERROR               = FORM_CD_MSG_NOTIFY_BASE,
};

constexpr int32_t FORM_CD_MAX_PEER_CONNECTIONS = 10;
constexpr int32_t FORM_CD_MAX_RETRY_COUNT = 3;
constexpr uint32_t FORM_CD_REQUEST_TIMEOUT_MS = 20 * 1000;

// QoS: QOS_TYPE_MAX_WAIT_TIMEOUT and QOS_TYPE_MAX_LATENCY share enum value 1 (mutually exclusive).
// Sync Bind uses MAX_WAIT_TIMEOUT; BindAsync uses MAX_LATENCY.
constexpr int32_t FORM_CD_QOS_MIN_BW = 40 * 1024;                // KBps
constexpr int32_t FORM_CD_QOS_MAX_WAIT_TIMEOUT_MS = 9 * 1000;   // ms, sync Bind timeout
constexpr int32_t FORM_CD_QOS_MAX_LATENCY_MS = 9 * 1000;             // ms, BindAsync route-selection
constexpr int32_t FORM_CD_QOS_MIN_LATENCY_MS = 2 * 1000;             // ms

constexpr uint32_t FORM_CD_BIND_WAIT_TIMEOUT_MS = FORM_CD_QOS_MAX_WAIT_TIMEOUT_MS + 5000;

constexpr const char *FORM_CD_SERVICE_TYPE = "ohos.form.svc";
constexpr int32_t FORM_CD_DEFAULT_DISPLAY_ID = 0;
constexpr int64_t FORM_CD_INVALID_FORM_ID = -1;
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CROSS_DEVICE_CONSTANTS_H
