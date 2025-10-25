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

#ifndef OHOS_FORM_FWK_THEME_FORM_CLIENT_H
#define OHOS_FORM_FWK_THEME_FORM_CLIENT_H
#ifdef THEME_MGR_ENABLE

#include <mutex>
#include <singleton.h>

#include "form_host_interface.h"
#include "iremote_proxy.h"
#include "theme_manager_service_interface.h"

#include "want.h"

namespace OHOS {
namespace AppExecFwk {

struct FormNotifyInfo {
    int64_t formId;
    AAFwk::Want want;
};

class FormNotifyInterface {
    /**
     * @brief Notify other module to add form.
     * @param info Add form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t AddForm(const FormNotifyInfo& info) = 0;

    /**
     * @brief Notify other module to delete forms.
     * @param formIds Forms to delete.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t DeleteForms(const std::vector<int64_t> &formIds) = 0;
};

class ThemeFormClient final : public DelayedRefSingleton<ThemeFormClient>, public FormNotifyInterface {
public:
    ThemeFormClient();
    ~ThemeFormClient();

    DISALLOW_COPY_AND_MOVE(ThemeFormClient);
    void OnRemoteSaDied(const wptr<IRemoteObject> &object);
    int32_t AddForm(const FormNotifyInfo& info);
    int32_t DeleteForms(const vector<int64_t> &formIds);

private:
    sptr<IThemeManagerService> GetProxy();

    void CreateThemeFormParcel(const FormNotifyInfo& info, ThemeManagerThemeFormInfoByParcel& parcel);
    ErrorCode ConvertIntToErrorCode(int32_t errorCode);
    void CleanResource();

    std::mutex themeSvcProxyMutex_;
    sptr<IThemeManagerService> themeSvcProxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};

class ThemeFormDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    ThemeFormDeathRecipient() {};
    ~ThemeFormDeathRecipient() = default;

    DISALLOW_COPY_AND_MOVE(ThemeFormDeathRecipient);
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;
};

class ThemeFormServiceProxy : public OHOS::IRemoteProxy<IThemeManagerService> {
public:
    explicit ThemeFormServiceProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IThemeManagerService>(object)
    {}
    ~ThemeFormServiceProxy() = default;
    DISALLOW_COPY_AND_MOVE(ThemeFormServiceProxy);

    ErrCode AddForm(const ThemeManagerThemeFormInfoByParcel& themeFormInfo);
    ErrCode DeleteForm(const std::vector<long> &formIds);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // THEME_MGR_ENABLE
#endif // OHOS_FORM_FWK_THEME_FORM_CLIENT_H