/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCE_H
#define FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCE_H

#include <string>
#include <mutex>
#include <condition_variable>
#include "parcel.h"
#include "errors.h"

namespace OHOS {
namespace AppExecFwk {
enum class FormUsageState {
    USED = 0,
    UNUSED,
};

enum class FormVisibilityType {
    UNKNOWN = 0,
    VISIBLE,
    INVISIBLE,
};

enum class LowMemoryRecycleStatus {
    RECYCLABLE,
    RECYCLED,
    NON_RECYCLABLE,
};

enum class ConditionUpdateType {
    NOCONDITON = 0,
    NETWORK,
};

struct FormInstance : public Parcelable {
    int64_t formId = 0;
    std::string formHostName = "";
    FormVisibilityType formVisiblity = FormVisibilityType::UNKNOWN;
    int32_t specification = 0;
    std::string bundleName = "";
    std::string moduleName = "";
    std::string abilityName = "";
    std::string formName = "";
    FormUsageState formUsageState = FormUsageState::USED;
    std::string description;
    int32_t appIndex = 0;
    int32_t userId = -1;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static FormInstance *Unmarshalling(Parcel &parcel);
};

struct Rect : public Parcelable {
    double left;
    double top;
    double width;
    double height;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static Rect *Unmarshalling(Parcel &parcel);
};

struct OverflowInfo : public Parcelable {
    Rect area;
    int32_t duration = -1;
    bool useDefaultAnimation = true;

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static OverflowInfo *Unmarshalling(Parcel &parcel);
};

struct PublishFormCrossBundleInfo : public Parcelable {
    std::string callerBundleName = "";
    std::string targetBundleName = "";
    std::string targetTemplateFormDetailId = "";

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static PublishFormCrossBundleInfo *Unmarshalling(Parcel &parcel);
};
} // namespace AppExecFwk

/* formId：the Id of form.
 * overflowInfo: overflow information, including overflow area and overflow duration.
 * isOverflow: whether overflow, true means request overflow, false means cancel overflow.
 * state：activation state, 1 means activate, 0 means deactivate.
 * condition：condition variable for thread synchronization
 * mutex：mutex locks for shared resources.
 * isReady：used to indicate whether the asynchronous operation is completed or not.
 * result：the result of the operation.
 */
typedef struct LiveFormInterfaceParam {
    std::string formId;
    AppExecFwk::OverflowInfo overflowInfo;
    bool isOverflow = true;
    int32_t state;
    std::condition_variable condition;
    std::mutex mutex;
    bool isReady = false;
    bool result = false;
    AppExecFwk::Rect formRect;
    std::unordered_map<std::string, std::string> liveFormStatusMap;
    ErrCode errCode = ERR_OK;
} LiveFormInterfaceParam;
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_OHOS_FORM_INSTANCE_H