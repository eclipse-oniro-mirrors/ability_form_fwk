/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_INFO_CONFIG_UPDATE_FILTER_H
#define OHOS_FORM_FWK_FORM_INFO_CONFIG_UPDATE_FILTER_H

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief This struct is mainly used by function SetConfigurationUpdateFlags as a ConfigurationUpdateFlags to retrieve
 * only configurationUpdateEnabled that has desired attributes, e.g. the fontConfigUpdateFlags switch status with
 * fontEnabled as specifed in FormInfoConfigUpdateFilter.
 */
struct FormInfoConfigUpdateFilter final : public Parcelable {
    // list of parameters
    bool fontEnabled;

    /**
     * @brief Serialize the list of parameters for IPC.
     *
     * @param parcel The container into which the serialized parameters write.
     * @return true when serialization is successful, false otherwise.
     */
    bool Marshalling(Parcel &parcel) const override;

    /**
     * @brief Deserialize the list of parameters from IPC
     *
     * @param parcel The container from which the serialized parameters read.
     * @return true when deserialization is successful, false otherwise.
     */
    static FormInfoConfigUpdateFilter *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif