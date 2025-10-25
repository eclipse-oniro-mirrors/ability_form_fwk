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

#ifdef THEME_MGR_ENABLE
#include "theme_manager_service_param.h"
#include "fms_log_wrapper.h"

namespace OHOS::AppExecFwk {
ThemeManagerThemeFormInfoByParcel::ThemeManagerThemeFormInfoByParcel()
{
}

bool ThemeManagerThemeFormInfoByParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(themeFormInfo_.themeFormId)) {
        return false;
    }
    if (!parcel.WriteInt64(themeFormInfo_.formId)) {
        return false;
    }
    if (!parcel.WriteString(themeFormInfo_.themeId)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(themeFormInfo_.themeFormDimension))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(themeFormInfo_.themeFormLocation))) {
        return false;
    }
    return true;
}

ThemeManagerThemeFormInfoByParcel *ThemeManagerThemeFormInfoByParcel::Unmarshalling(Parcel &parcel)
{
    ThemeManagerThemeFormInfoByParcel *obj = new (std::nothrow) ThemeManagerThemeFormInfoByParcel();
    if (obj == nullptr) {
        HILOG_ERROR("new ThemeManagerThemeFormInfoByParcel is nullptr");
        return nullptr;
    }
    obj->themeFormInfo_.themeFormId = parcel.ReadString();
    obj->themeFormInfo_.formId = parcel.ReadInt64();
    obj->themeFormInfo_.themeId = parcel.ReadString();
    int32_t themeFormDimensionValue = parcel.ReadInt32();
    int32_t themeFormLocationValue = parcel.ReadInt32();
    obj->themeFormInfo_.themeFormDimension = static_cast<ThemeFormDimension>(themeFormDimensionValue);
    obj->themeFormInfo_.themeFormLocation = static_cast<ThemeFormLocation>(themeFormLocationValue);
    return obj;
}

} // namespace OHOS::AppExecFwk
#endif // THEME_MGR_ENABLE