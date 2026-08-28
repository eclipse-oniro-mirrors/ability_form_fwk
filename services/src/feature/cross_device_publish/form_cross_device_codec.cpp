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

#include "feature/cross_device_publish/form_cross_device_codec.h"

#include "fms_log_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
void WriteBe32U(uint8_t *dst, uint32_t v)
{
    dst[0] = static_cast<uint8_t>((v >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((v >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((v >> 8) & 0xFF);
    dst[3] = static_cast<uint8_t>(v & 0xFF);
}
uint32_t ReadBe32U(const uint8_t *src)
{
    return (static_cast<uint32_t>(src[0]) << 24) | (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) | static_cast<uint32_t>(src[3]);
}

// Reuses Marshalling as single source of truth with IPC.
template <typename T>
bool MarshallTo(const T &obj, std::string &out)
{
    MessageParcel parcel;
    if (!obj.Marshalling(parcel)) {
        HILOG_ERROR("Marshalling failed");
        return false;
    }
    const uint8_t *data = reinterpret_cast<const uint8_t *>(parcel.GetData());
    size_t size = parcel.GetDataSize();
    if (data == nullptr || size == 0) {
        HILOG_ERROR("empty parcel data");
        return false;
    }
    out.assign(reinterpret_cast<const char *>(data), size);
    return true;
}

// WriteUnpadBuffer then Unmarshalling from position 0.
template <typename T>
bool UnmarshallFrom(const std::string &payload, T &obj)
{
    MessageParcel parcel;
    if (!parcel.WriteUnpadBuffer(payload.data(), payload.size())) {
        HILOG_ERROR("WriteUnpadBuffer failed, size=%{public}zu", payload.size());
        return false;
    }
    std::unique_ptr<T> ptr(T::Unmarshalling(parcel));
    if (ptr == nullptr) {
        HILOG_ERROR("Unmarshalling failed");
        return false;
    }
    obj = std::move(*ptr);
    return true;
}

bool BuildFrame(FormCdMsgType msgType, uint32_t seqId, const std::string &payload, std::string &out)
{
    if (payload.size() > FORM_CD_MAX_PAYLOAD) {
        HILOG_ERROR("payload too large:%{public}zu", payload.size());
        return false;
    }
    out.resize(FORM_CD_FRAME_HEADER_SIZE);
    auto *hdr = reinterpret_cast<uint8_t *>(out.data());
    WriteBe32U(hdr, FORM_CD_MAGIC);
    hdr[4] = FORM_CD_PROTO_VERSION;
    hdr[5] = static_cast<uint8_t>(msgType);
    hdr[6] = 0; // reserved
    hdr[7] = 0;
    WriteBe32U(hdr + 8, seqId);
    WriteBe32U(hdr + 12, static_cast<uint32_t>(payload.size()));
    out += payload;
    return true;
}
} // namespace

bool FormCrossDeviceCodec::BuildRawFrame(FormCdMsgType msgType, uint32_t seqId,
    const std::string &payload, std::string &out)
{
    return BuildFrame(msgType, seqId, payload, out);
}

bool FormCrossDeviceCodec::EncodeRequest(FormCdMsgType msgType, uint32_t seqId,
    const FormCrossDeviceRequest &req, std::string &out)
{
    std::string payload;
    if (!MarshallTo(req, payload)) {
        return false;
    }
    return BuildFrame(msgType, seqId, payload, out);
}

bool FormCrossDeviceCodec::EncodeResult(FormCdMsgType msgType, uint32_t seqId,
    const PublishFormCrossDeviceResult &res, std::string &out)
{
    std::string payload;
    if (!MarshallTo(res, payload)) {
        return false;
    }
    return BuildFrame(msgType, seqId, payload, out);
}

bool FormCrossDeviceCodec::DecodeRequest(const std::string &payload, FormCrossDeviceRequest &req)
{
    return UnmarshallFrom(payload, req);
}

bool FormCrossDeviceCodec::DecodeResult(const std::string &payload, PublishFormCrossDeviceResult &res)
{
    return UnmarshallFrom(payload, res);
}

void FormCrossDeviceCodec::Feed(int32_t fd, const void *data, uint32_t len, const FrameHandler &onFrame)
{
    if (data == nullptr || len == 0 || fd < 0) {
        return;
    }
    const auto *bytes = static_cast<const uint8_t *>(data);
    std::string snapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string &buf = fragMap_[fd];
        buf.append(reinterpret_cast<const char *>(bytes), len);
        snapshot.swap(buf);
    }

    size_t consumed = 0;
    while (snapshot.size() - consumed >= FORM_CD_FRAME_HEADER_SIZE) {
        const uint8_t *hdr = reinterpret_cast<const uint8_t *>(snapshot.data()) + consumed;
        uint32_t magic = ReadBe32U(hdr);
        uint8_t version = hdr[4];
        auto msgType = static_cast<FormCdMsgType>(hdr[5]);
        uint32_t seqId = ReadBe32U(hdr + 8);
        uint32_t payloadLen = ReadBe32U(hdr + 12);
        if (magic != FORM_CD_MAGIC || version != FORM_CD_PROTO_VERSION ||
            payloadLen > FORM_CD_MAX_PAYLOAD) {
            HILOG_ERROR("dirty frame, magic=0x%{public}x ver=%{public}d payloadLen=%{public}u, drop fd=%{public}d",
                magic, version, payloadLen, fd);
            return; // cannot locate next frame boundary
        }
        if (snapshot.size() - consumed < FORM_CD_FRAME_HEADER_SIZE + payloadLen) {
            break;
        }
        std::string payload(snapshot, consumed + FORM_CD_FRAME_HEADER_SIZE, payloadLen);
        consumed += FORM_CD_FRAME_HEADER_SIZE + payloadLen;
        if (onFrame) {
            onFrame(msgType, seqId, payload);
        }
    }

    if (consumed > 0) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string &buf = fragMap_[fd];
        if (snapshot.size() > consumed) {
            buf = snapshot.substr(consumed);
        } else {
            buf.clear();
        }
    }
}

void FormCrossDeviceCodec::Clear(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    fragMap_.erase(fd);
}
} // namespace AppExecFwk
} // namespace OHOS
