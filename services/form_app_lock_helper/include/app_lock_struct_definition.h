/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef APP_LOCK_STRUCT_DEFINITION_H
#define APP_LOCK_STRUCT_DEFINITION_H

#include <vector>
#include <string>

#include "parcel.h"

namespace OHOS::AppSecurityPrivacy::AppLock {
struct AppInfo final : public Parcelable {
public:
    AppInfo() = default;

    AppInfo(std::string rBundleName, int32_t inAppIndex);

    AppInfo(const AppInfo &appInfo);
    AppInfo &operator = (const AppInfo &appInfo);
    AppInfo(AppInfo &&appInfo) noexcept;
    AppInfo &operator = (AppInfo &&appInfo) noexcept;

    bool Marshalling(Parcel &out) const override;

    static AppInfo *Unmarshalling(Parcel &in);

    std::string ToString() const;

    std::string bundleName;

    int32_t appIndex = 0;

    bool operator == (const AppInfo &appInfo) const

    {
        return (appIndex == appInfo.appIndex) && (bundleName == appInfo.bundleName);
    }

    struct Hash {
        std::size_t operator () (const AppInfo &appInfo) const
        {
            std::size_t h1 = std::hash<std::string>()(appInfo.bundleName);
            std::size_t h2 = std::hash<int32_t>()(appInfo.appIndex);
            return h1 ^ (h2 << 1);
        }
    };
};

struct SwitchState final : public Parcelable {
public:
    SwitchState() = default;

    SwitchState(std::string rBundleName, int32_t inAppIndex, int32_t inUserId, bool isEnabledState);

    SwitchState(const SwitchState &switchState);
    SwitchState &operator = (const SwitchState &switchState);
    SwitchState(SwitchState &&switchState) noexcept;
    SwitchState &operator = (SwitchState &&switchState) noexcept;

    bool Marshalling(Parcel &out) const override;

    static SwitchState *Unmarshalling(Parcel &in);

    AppInfo appInfo;

    int32_t userId;

    bool isEnabled = false;
};

struct AppProtectedState final : public Parcelable {
public:
    AppProtectedState() = default;

    AppProtectedState(std::string rBundleName, int32_t inAppIndex, int32_t inUserId, bool protectedState);

    AppProtectedState(const AppProtectedState &appProtectedState);
    AppProtectedState &operator = (const AppProtectedState &appProtectedState);
    AppProtectedState(AppProtectedState &&appProtectedState) noexcept;
    AppProtectedState &operator = (AppProtectedState &&appProtectedState) noexcept;

    bool Marshalling(Parcel &out) const override;

    static AppProtectedState *Unmarshalling(Parcel &in);

    AppInfo appInfo;

    int32_t userId;

    bool isProtected = false;
};

struct ExemptedBundleInfos final : public Parcelable {
public:
    ExemptedBundleInfos() = default;

    ExemptedBundleInfos(std::string bundleName, std::string appIdentifier, std::string appId);

    ExemptedBundleInfos(const ExemptedBundleInfos &exemptedBundleInfos);
    ExemptedBundleInfos &operator = (const ExemptedBundleInfos &exemptedBundleInfos);
    ExemptedBundleInfos(ExemptedBundleInfos &&exemptedBundleInfos) noexcept;
    ExemptedBundleInfos &operator = (ExemptedBundleInfos &&exemptedBundleInfos) noexcept;

    bool Marshalling(Parcel &out) const override;

    static ExemptedBundleInfos *Unmarshalling(Parcel &in);

    std::string bundleName;
    std::string appIdentifier;
    std::string appId;
};

struct AllowedAuthType final : public Parcelable {
public:
    AllowedAuthType() = default;

    AllowedAuthType(int32_t inAuthType, int32_t inUserId, bool inIsAllowed);

    AllowedAuthType(const AllowedAuthType &allowedAuthType);
    AllowedAuthType &operator = (const AllowedAuthType &allowedAuthType);
    AllowedAuthType(AllowedAuthType &&allowedAuthType) noexcept;
    AllowedAuthType &operator = (AllowedAuthType &&allowedAuthType) noexcept;

    bool Marshalling(Parcel &out) const override;

    static AllowedAuthType *Unmarshalling(Parcel &in);

    int32_t authType = 0;

    int32_t userId = 0;

    bool isAllowed = false;
};
} // namespace OHOS::AppSecurityPrivacy::AppLock

#endif // APP_LOCK_STRUCT_DEFINITION_H
