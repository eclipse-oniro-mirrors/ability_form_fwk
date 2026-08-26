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

#ifndef OHOS_FORM_FWK_FORM_CROSS_DEVICE_REQUEST_H
#define OHOS_FORM_FWK_FORM_CROSS_DEVICE_REQUEST_H

#include <cstdint>
#include <string>
#include <vector>

#include "errors.h"
#include "form_cross_device_constants.h"
#include "form_service_info.h"
#include "iremote_broker.h"
#include "parcel.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief Cross-device publish request.
 *        peerNetworkId identifies the target device; FMS gateway handles internal routing.
 *        peerServiceId from DM discovery, used for SoftBus ServiceSocket cross-pairing.
 */
struct FormCrossDeviceRequest : public Parcelable {
    std::string peerNetworkId;
    int64_t peerServiceId = 0;
    OHOS::AAFwk::Want want;
    std::string formProviderData;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormCrossDeviceRequest *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Cross-device publish result. Sent back after peer dispatch,
 *        or constructed by FMS on local bind failure.
 */
struct PublishFormCrossDeviceResult : public Parcelable {
    int32_t errCode = ERR_OK;
    int64_t formId = FORM_CD_INVALID_FORM_ID;

    PublishFormCrossDeviceResult() = default;
    PublishFormCrossDeviceResult(int32_t code, int64_t id) : errCode(code), formId(id) {}

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static PublishFormCrossDeviceResult *Unmarshalling(Parcel &parcel);
};

/**
 * @brief Publish result callback: FMS holds its Proxy and pushes the connection/publish
 *        result back to the caller asynchronously.
 */
class IFormCrossDevicePublishCallback : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormCrossDevicePublishCallback");

    /**
     * @brief Push publish result (success or failure).
     * @param result publish result.
     */
    virtual void OnResult(const PublishFormCrossDeviceResult &result) = 0;

    enum class Message {
        FORM_CD_CALLBACK_ON_RESULT = 1,
    };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_CROSS_DEVICE_REQUEST_H
