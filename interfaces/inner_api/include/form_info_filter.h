/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_INFO_FILTER_H
#define OHOS_FORM_FWK_FORM_INFO_FILTER_H

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief This struct is mainly used by function getFormsInfo as a filter to retrieve only formInfos
 * that has desired attributes, e.g. the formInfo is belong to a module with the same moduleName as specifed
 * in FormInfoFilter.
 */
struct FormInfoFilter final : public Parcelable {
    // list of parameters
    std::string moduleName = "";

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
    static FormInfoFilter *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif