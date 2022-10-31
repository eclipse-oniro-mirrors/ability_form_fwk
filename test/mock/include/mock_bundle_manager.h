/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_MOCK_BUNDLE_MANAGER_H
#define OHOS_FORM_FWK_MOCK_BUNDLE_MANAGER_H

#include <vector>

#include "ability_info.h"
#include "application_info.h"
#include "bundle_mgr_interface.h"
#include "gmock/gmock.h"
#include "iremote_proxy.h"
#include "iremote_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
const int32_t APP_600 = 600;

class BundleMgrProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit BundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
    {}
    virtual ~BundleMgrProxy()
    {}

    MOCK_METHOD5(QueryAbilityInfo, bool(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &callBack));
    bool QueryAbilityInfo(const AAFwk::Want &want, AbilityInfo &abilityInfo) override
    {
        return true;
    }

    std::string GetAppType(const std::string &bundleName) override
    {
        return "system";
    }

    virtual int GetUidByBundleName(const std::string &bundleName, const int userId) override
    {
        if (bundleName.compare("com.form.host.app600") == 0) {
            return APP_600;
        }
        return 0;
    }

    virtual bool GetBundleNameForUid(const int uid, std::string &bundleName) override
    {
        bundleName = "com.form.provider.service";
        return true;
    }

    virtual bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfo) override;
    virtual bool GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfo) override;
};

class BundleMgrStub : public IRemoteStub<IBundleMgr> {
public:
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
};

class BundleMgrService : public BundleMgrStub {
public:
    static bool IsSystemApp;

    bool QueryAbilityInfo(const AAFwk::Want &want, AbilityInfo &abilityInfo) override;
    MOCK_METHOD5(QueryAbilityInfo, bool(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
        const sptr<IRemoteObject> &callBack));

    virtual int GetUidByBundleName(const std::string &bundleName, const int userId) override;

    virtual bool GetBundleInfo(
        const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId) override;

    virtual bool GetBundleNameForUid(const int uid, std::string &bundleName) override
    {
        bundleName = "com.form.provider.service";
        return true;
    };

    virtual std::string GetAppType(const std::string &bundleName);

    virtual bool CheckIsSystemAppByUid(const int uid) override
    {
        return IsSystemApp;
    }

    virtual bool GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfo) override;
    virtual bool GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfo) override;

    virtual bool ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
        AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo) override
    {
        abilityInfo.name = "MainAbility";
        abilityInfo.bundleName = "com.ohos.launcher";
        extensionInfo.name = "MainAbility";
        extensionInfo.bundleName = "com.ohos.launcher";
        return true;
    }
};

class MockBundleMgrService : public BundleMgrService {
public:
    MOCK_METHOD(bool, GetBundleInfo,
        (const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId), (override));
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_MOCK_BUNDLE_MANAGER_H
