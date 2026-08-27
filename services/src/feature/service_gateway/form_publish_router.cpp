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

#include "feature/service_gateway/form_publish_router.h"

#include <cinttypes>

#include "common/util/form_util.h"
#include "feature/cross_device_publish/form_cross_device_codec.h"
#include "feature/service_discovery/form_service_discovery.h"
#include "form_cross_device_constants.h"
#include "form_cross_device_publish_callback_proxy.h"
#include "form_mgr/form_mgr_adapter_facade.h"
#include "form_mgr_errors.h"
#include "form_provider_data.h"
#include "form_service_constants.h"
#include "fms_log_wrapper.h"
#include "hitrace_meter.h"
#include "iremote_broker.h"
#include "ipc_skeleton.h"
#include "xcollie/xcollie.h"

namespace OHOS {
namespace AppExecFwk {

FormPublishRouter::FormPublishRouter()
{}

FormPublishRouter::~FormPublishRouter()
{}

void FormPublishRouter::Init()
{
    EnsureMembers();
}

void FormPublishRouter::EnsureMembers()
{
    std::call_once(initOnce_, [this]() {
        serviceProxy_ = std::make_shared<FormServiceProxy>(std::make_shared<DmServiceAdapter>());
        connectionPool_ = std::make_shared<FormConnectionPool>();
        connectionPool_->SetFrameHandler(this);
    });
}

ErrCode FormPublishRouter::StartListen(int64_t serviceId)
{
    EnsureMembers();
    return connectionPool_->StartListen(serviceId);
}

void FormPublishRouter::StopListen(int64_t serviceId)
{
    EnsureMembers();
    connectionPool_->StopListen(serviceId);
}

ErrCode FormPublishRouter::RequestPublish(const FormCrossDeviceRequest &request,
    const sptr<IRemoteObject> &callerToken, const sptr<IRemoteObject> &callback)
{
    EnsureMembers();
    sptr<IFormCrossDevicePublishCallback> cb;
    ErrCode ret = ValidatePublishParams(request, callback, cb);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = EnsurePeerConnection(request.peerNetworkId, request.peerServiceId);
    if (ret != ERR_OK) {
        return ret;
    }
    uint32_t seqId = ++seqGen_;
    RegisterPublishResponseHandler(seqId, request.peerNetworkId, cb);
    ret = SendPublishFrame(request, seqId);
    if (ret != ERR_OK) {
        connectionPool_->UnregisterResponseHandler(seqId);
        return ret;
    }
    StartPublishTimer(seqId, cb);
    HILOG_INFO("publish request sent: seq=%{public}u peer=%{public}s",
        seqId, request.peerNetworkId.c_str());
    return ERR_OK;
}

ErrCode FormPublishRouter::ValidatePublishParams(const FormCrossDeviceRequest &request,
    const sptr<IRemoteObject> &callback, sptr<IFormCrossDevicePublishCallback> &outCb)
{
    if (request.peerNetworkId.empty()) {
        HILOG_ERROR("invalid request: peerNetworkId empty");
        return ERR_APPEXECFWK_FORM_CD_INVALID_PARAM;
    }
    if (callback == nullptr) {
        HILOG_ERROR("callback null");
        return ERR_APPEXECFWK_FORM_CD_INVALID_PARAM;
    }
    auto cb = iface_cast<IFormCrossDevicePublishCallback>(callback);
    if (cb == nullptr) {
        HILOG_ERROR("iface_cast IFormCrossDevicePublishCallback failed");
        return ERR_APPEXECFWK_FORM_CD_INVALID_PARAM;
    }
    outCb = cb;
    return ERR_OK;
}

ErrCode FormPublishRouter::EnsurePeerConnection(const std::string &peerNetworkId, int64_t peerServiceId)
{
    if (!FormServiceDiscovery::GetInstance().IsDiscoveredPeer(peerNetworkId, peerServiceId)) {
        HILOG_ERROR("peer not discovered: networkId=%{public}s serviceId=%{public}" PRId64,
            peerNetworkId.c_str(), peerServiceId);
        return ERR_APPEXECFWK_FORM_CD_PEER_SERVICE_UNAVAILABLE;
    }
    ErrCode connRet = connectionPool_->GetOrCreateConnection(peerNetworkId, peerServiceId, true);
    if (connRet != ERR_OK) {
        HILOG_ERROR("GetOrCreateConnection failed for peer:%{public}s, ret=%{public}d",
            peerNetworkId.c_str(), connRet);
        return ERR_APPEXECFWK_FORM_CD_PEER_SERVICE_UNAVAILABLE;
    }
    return ERR_OK;
}

void FormPublishRouter::RegisterPublishResponseHandler(uint32_t seqId,
    const std::string &peerNetworkId, const sptr<IFormCrossDevicePublishCallback> &cb)
{
    connectionPool_->RegisterResponseHandler(seqId, peerNetworkId,
        [this, cb](FormCdMsgType msgType, uint32_t seqId, const std::string &payload) {
            CancelPendingTimer(seqId);
            HandlePublishResponse(msgType, seqId, payload, cb);
        });
}

void FormPublishRouter::HandlePublishResponse(FormCdMsgType msgType, uint32_t seqId,
    const std::string &payload, const sptr<IFormCrossDevicePublishCallback> &cb)
{
    if (msgType == FormCdMsgType::RESPONSE_PUBLISH) {
        PublishFormCrossDeviceResult res;
        if (!FormCrossDeviceCodec::DecodeResult(payload, res)) {
            HILOG_ERROR("DecodeResult failed for RESPONSE_PUBLISH seq=%{public}u", seqId);
            res = PublishFormCrossDeviceResult{ ERR_APPEXECFWK_FORM_CD_CODEC_FAILED, FORM_CD_INVALID_FORM_ID };
        }
        HILOG_INFO("RESPONSE_PUBLISH received: seq=%{public}u formId=%{public}" PRId64,
            seqId, res.formId);
        cb->OnResult(res);
        return;
    }
    if (msgType == FormCdMsgType::ERROR) {
        HILOG_WARN("ERROR response received for seq=%{public}u", seqId);
        cb->OnResult(PublishFormCrossDeviceResult{
            ERR_APPEXECFWK_FORM_CD_PEER_APP_NOT_INSTALLED, FORM_CD_INVALID_FORM_ID });
        return;
    }
    HILOG_ERROR("unexpected msgType=%{public}u for REQUEST_PUBLISH seq=%{public}u",
        static_cast<uint32_t>(msgType), seqId);
    cb->OnResult(PublishFormCrossDeviceResult{
        ERR_APPEXECFWK_FORM_CD_INVALID_MSG_TYPE, FORM_CD_INVALID_FORM_ID });
}

ErrCode FormPublishRouter::SendPublishFrame(const FormCrossDeviceRequest &request, uint32_t seqId)
{
    std::string frame;
    if (!FormCrossDeviceCodec::EncodeRequest(FormCdMsgType::REQUEST_PUBLISH, seqId, request, frame)) {
        HILOG_ERROR("encode request failed");
        return ERR_APPEXECFWK_FORM_CD_CODEC_FAILED;
    }
    ErrCode sendRet = connectionPool_->SendRawFrame(request.peerNetworkId, frame);
    if (sendRet != ERR_OK) {
        HILOG_ERROR("SendRawFrame failed for peer:%{public}s, ret=%{public}d",
            request.peerNetworkId.c_str(), sendRet);
        return ERR_APPEXECFWK_FORM_CD_PEER_SERVICE_UNAVAILABLE;
    }
    return ERR_OK;
}

void FormPublishRouter::StartPublishTimer(uint32_t seqId, const sptr<IFormCrossDevicePublishCallback> &cb)
{
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        "FormPublishTimeout", FORM_CD_REQUEST_TIMEOUT_MS,
        [this, seqId, cb](void *) {
            HILOG_ERROR("publish request timed out: seq=%{public}u", seqId);
            connectionPool_->UnregisterResponseHandler(seqId);
            cb->OnResult(PublishFormCrossDeviceResult{
                ERR_APPEXECFWK_FORM_CD_REQUEST_TIMEOUT, FORM_CD_INVALID_FORM_ID });
            std::lock_guard<std::mutex> lock(timerMutex_);
            pendingTimers_.erase(seqId);
        }, nullptr, HiviewDFX::XCOLLIE_FLAG_NOOP);
    std::lock_guard<std::mutex> lock(timerMutex_);
    pendingTimers_[seqId] = timerId;
}

ErrCode FormPublishRouter::HandleIncomingPublish(const FormCrossDeviceRequest &req, PublishFormCrossDeviceResult &res)
{
    HILOG_INFO("remote gateway: incoming publish from peer=%{public}s",
        req.peerNetworkId.c_str());

    int32_t userId = -1;
    if (!FormServiceDiscovery::GetInstance().GetUserIdByServiceId(req.peerServiceId, userId)) {
        HILOG_ERROR("serviceId not found in local registration, serviceId=%{public}" PRId64, req.peerServiceId);
        res.errCode = ERR_APPEXECFWK_FORM_CD_PEER_SERVICE_UNAVAILABLE;
        return ERR_APPEXECFWK_FORM_CD_PEER_SERVICE_UNAVAILABLE;
    }

    Want want(req.want);
    int64_t formId = -1;
    std::unique_ptr<FormProviderData> formProviderData;
    if (!req.formProviderData.empty()) {
        formProviderData = std::make_unique<FormProviderData>(req.formProviderData);
    }
    ErrCode ret = FormMgrAdapterFacade::GetInstance().HandleCrossDevicePublish(want, userId, formId, formProviderData);
    if (ret != ERR_OK) {
        HILOG_ERROR("HandleCrossDevicePublish failed, ret=%{public}d", ret);
        res.errCode = ret;
        return ret;
    }
    res.formId = formId;
    return ERR_OK;
}

void FormPublishRouter::OnFrame(int32_t fd, FormCdMsgType msgType,
    uint32_t seqId, const std::string &payload)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("OnFrame: fd=%{public}d msgType=%{public}u seq=%{public}u payloadLen=%{public}zu",
        fd, static_cast<uint32_t>(msgType), seqId, payload.size());
    switch (msgType) {
        case FormCdMsgType::REQUEST_PUBLISH: {
            FormCrossDeviceRequest req;
            if (!FormCrossDeviceCodec::DecodeRequest(payload, req)) {
                HILOG_ERROR("decode REQUEST_PUBLISH failed seq=%{public}u", seqId);
                SendErrorFrame(fd, seqId, ERR_APPEXECFWK_FORM_CD_CODEC_FAILED);
                return;
            }
            PublishFormCrossDeviceResult res;
            ErrCode ret = HandleIncomingPublish(req, res);
            if (ret != ERR_OK) {
                res.errCode = ret;
            }
            std::string frame;
            if (FormCrossDeviceCodec::EncodeResult(FormCdMsgType::RESPONSE_PUBLISH, seqId, res, frame)) {
                SendResponseFrame(fd, frame);
            } else {
                HILOG_ERROR("EncodeResult failed for RESPONSE_PUBLISH seq=%{public}u", seqId);
                SendErrorFrame(fd, seqId, ERR_APPEXECFWK_FORM_CD_CODEC_FAILED);
            }
            break;
        }
        default: {
            HILOG_ERROR("unexpected msgType=%{public}u from fd=%{public}d",
                static_cast<uint32_t>(msgType), fd);
            SendErrorFrame(fd, seqId, ERR_APPEXECFWK_FORM_CD_INVALID_MSG_TYPE);
            break;
        }
    }
}

void FormPublishRouter::SendResponseFrame(int32_t fd, const std::string &frame)
{
    if (connectionPool_ == nullptr) {
        HILOG_ERROR("connectionPool is null, cannot send response frame");
        return;
    }
    ErrCode ret = connectionPool_->SendRawFrameByFd(fd, frame);
    if (ret != ERR_OK) {
        HILOG_ERROR("SendResponseFrame failed: fd=%{public}d ret=%{public}d", fd, ret);
    } else {
        HILOG_DEBUG("SendResponseFrame ok: fd=%{public}d size=%{public}zu", fd, frame.size());
    }
}

void FormPublishRouter::SendErrorFrame(int32_t fd, uint32_t seqId, ErrCode errCode)
{
    std::string errFrame;
    if (!FormCrossDeviceCodec::EncodeResult(
        FormCdMsgType::ERROR, seqId,
        PublishFormCrossDeviceResult{ errCode, FORM_CD_INVALID_FORM_ID }, errFrame)) {
        HILOG_ERROR("EncodeResult ERROR failed seq=%{public}u", seqId);
        return;
    }
    SendResponseFrame(fd, errFrame);
}

void FormPublishRouter::CancelPendingTimer(uint32_t seqId)
{
    int32_t timerId = -1;
    {
        std::lock_guard<std::mutex> lock(timerMutex_);
        auto it = pendingTimers_.find(seqId);
        if (it != pendingTimers_.end()) {
            timerId = it->second;
            pendingTimers_.erase(it);
        }
    }
    if (timerId >= 0) {
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
    }
}

std::shared_ptr<FormServiceProxy> FormPublishRouter::GetServiceProxy()
{
    EnsureMembers();
    return serviceProxy_;
}

void FormPublishRouter::Dump(std::string &result)
{
    EnsureMembers();
    result += "== FormPublishRouter ==\n";
    if (serviceProxy_ != nullptr) {
        serviceProxy_->Dump(result);
    }
    if (connectionPool_ != nullptr) {
        connectionPool_->Dump(result);
    }
}

} // namespace AppExecFwk
} // namespace OHOS
