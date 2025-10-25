/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_THEME_MANAGER_SERVICE_PARAM_H
#define OHOS_FORM_FWK_THEME_MANAGER_SERVICE_PARAM_H

#ifdef THEME_MGR_ENABLE
#include <string>

#include "parcel.h"
#include "want_params.h"

namespace OHOS::AppExecFwk {

enum ThemeFormDimension {
    DIMENSION_1_1 = 0,
    DIMENSION_1_2,
    DIMENSION_2_1,
    DIMENSION_2_2,
    DIMENSION_2_4,
    DIMENSION_4_2,
    DIMENSION_4_4,
    DIMENSION_4_6,
    DIMENSION_6_4,
};

enum ThemeFormLocation { LOCATION_LAUNCHER = 0, LOCATION_UNLOCK, LOCATION_NEGATIVE_SCREEN };

struct ThemeFormInfo {
    std::string themeFormId;
    int64_t formId;
    std::string themeId;
    ThemeFormDimension themeFormDimension;
    ThemeFormLocation themeFormLocation;

    ThemeFormInfo()
    {
        themeFormId = "";
        formId = 0;
        themeId = "";
        themeFormDimension = DIMENSION_1_1;
        themeFormLocation = LOCATION_LAUNCHER;
    }

    ThemeFormInfo(const std::string &id, int64_t formId, const std::string &themeId,
        ThemeFormDimension dimension, ThemeFormLocation location)
    {
        this->themeFormId = id;
        this->formId = formId;
        this->themeId = themeId;
        this->themeFormDimension = dimension;
        this->themeFormLocation = location;
    }
};

enum ErrorCode : uint32_t {
    NO_ERROR = 0,
    NO_PERMISSION,
    NOT_SYSTEM_APP,
    IPC_FAILED,
    THEME_NULLPTR,
    FILE_EXCEPTION,
    PACKAGE_OVERSIZED,
    IS_ACTIVATING,
    PACKAGE_FORMAT_ERROR,
    SA_UNLOADING,
    DATABASE_ERROR,
    INTERNAL_ERROR,
    DELETE_FAILED,
    INVALID_VALUE,
    E_UNKNOWN,
    ACCOUNT_CHANGED_ERROR
};

class ThemeManagerThemeFormInfoByParcel final : public Parcelable {
public:
    ThemeManagerThemeFormInfoByParcel();
    ~ThemeManagerThemeFormInfoByParcel() = default;

    virtual bool Marshalling(Parcel &parcel) const override;
    static ThemeManagerThemeFormInfoByParcel *Unmarshalling(Parcel &parcel);
    ThemeFormInfo themeFormInfo_;
};

} // namespace OHOS::AppExecFwk
#endif // THEME_MGR_ENABLE
#endif // OHOS_FORM_FWK_THEME_MANAGER_SERVICE_PARAM_H