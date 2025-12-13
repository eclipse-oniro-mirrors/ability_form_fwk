/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_JS_FORM_PROVIDER_H
#define OHOS_FORM_FWK_JS_FORM_PROVIDER_H

#include "ability.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_provider_delegate_stub.h"
#include "form_provider_info.h"
#include "napi_form_util.h"
#include "template_form_detail_info.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nlohmann/json.hpp"
#include "want.h"
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
struct RequestPublishFormCallbackInfo {
    Want want {};
    bool withFormBindingData = false;
    std::unique_ptr<OHOS::AppExecFwk::FormProviderData> formProviderData = nullptr;
    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
};

struct AsyncIsRequestPublishFormSupportedCallbackInfo : AsyncCallbackInfoBase {
    bool result = false;

    explicit AsyncIsRequestPublishFormSupportedCallbackInfo(napi_env env) : AsyncCallbackInfoBase(env) {};
    ~AsyncIsRequestPublishFormSupportedCallbackInfo() override = default;
};

napi_value NAPI_RequestPublishForm(napi_env env, napi_callback_info info);

/**
 * @brief Check if the request to publish a form to the form host is supported.
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] info This is an opaque pointer that is used to represent a JavaScript value
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 *         which is true if the request of publishing form is supported and false otherwise
 */
napi_value NAPI_IsRequestPublishFormSupported(napi_env env, napi_callback_info info);

class JsFormProvider {
public:
    JsFormProvider() = default;
    ~JsFormProvider() = default;

    static void Finalizer(napi_env env, void* data, void* hint);
    static napi_value GetFormsInfo(napi_env env, napi_callback_info info);
    static napi_value SetFormNextRefreshTime(napi_env env, napi_callback_info info);
    static napi_value UpdateForm(napi_env env, napi_callback_info info);
    static napi_value IsRequestPublishFormSupported(napi_env env, napi_callback_info info);
    static napi_value RequestPublishForm(napi_env env, napi_callback_info info);
    static napi_value GetPublishedFormInfoById(napi_env env, napi_callback_info info);
    static napi_value GetPublishedFormInfos(napi_env env, napi_callback_info info);
    static napi_value OpenFormManager(napi_env env, napi_callback_info info);
    static napi_value OpenFormManagerCrossBundle(napi_env env, napi_callback_info info);
    static napi_value OpenFormEditAbility(napi_env env, napi_callback_info info);
    static napi_value CloseFormEditAbility(napi_env env, napi_callback_info info);
    static napi_value RequestOverflow(napi_env env, napi_callback_info info);
    static napi_value CancelOverflow(napi_env env, napi_callback_info info);
    static napi_value ActivateSceneAnimation(napi_env env, napi_callback_info info);
    static napi_value DeactivateSceneAnimation(napi_env env, napi_callback_info info);
    static napi_value GetFormRect(napi_env env, napi_callback_info info);
    static napi_value GetPublishedRunningFormInfoById(napi_env env, napi_callback_info info);
    static napi_value GetPublishedRunningFormInfos(napi_env env, napi_callback_info info);
    static napi_value ReloadForms(napi_env env, napi_callback_info info);
    static napi_value ReloadAllForms(napi_env env, napi_callback_info info);
    static napi_value RegisterPublishFormCrossBundleControl(napi_env env, napi_callback_info info);
    static napi_value UnregisterPublishFormCrossBundleControl(napi_env env, napi_callback_info info);
    static napi_value UpdateTemplateFormDetailInfo(napi_env env, napi_callback_info info);

private:
    napi_value OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetPublishedFormInfoById(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetPublishedFormInfos(napi_env env, size_t argc, napi_value* argv);
    napi_value OnOpenFormManager(napi_env env, size_t argc, napi_value* argv);
    napi_value OnOpenFormManagerCrossBundle(napi_env env, size_t argc, napi_value* argv);
    napi_value OnSetFormNextRefreshTime(napi_env env, size_t argc, napi_value* argv);
    napi_value OnUpdateForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnIsRequestPublishFormSupported(napi_env env, size_t argc, napi_value* argv);
    napi_value OnRequestPublishForm(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetFormRect(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetPublishedRunningFormInfoById(napi_env env, size_t argc, napi_value* argv);
    napi_value OnGetPublishedRunningFormInfos(napi_env env, size_t argc, napi_value* argv);
    napi_value OnReloadForms(napi_env env, size_t argc, napi_value* argv);
    napi_value OnReloadAllForms(napi_env env, size_t argc, napi_value* argv);
    napi_value OnRegisterPublishFormCrossBundleControl(napi_env env, size_t argc, napi_value* argv);
    napi_value OnUnregisterPublishFormCrossBundleControl(napi_env env, size_t argc, napi_value* argv);
    napi_value OnUpdateTemplateFormDetailInfo(napi_env env, size_t argc, napi_value* argv);

    bool ConvertFromDataProxies(napi_env env, napi_value jsValue,
        std::vector<AppExecFwk::FormDataProxy> &formDataProxies);
    bool ConvertFormDataProxy(napi_env env, napi_value jsValue, AppExecFwk::FormDataProxy &formDataProxy);

    bool OnGetFormsInfoParseParam(NapiParamPackage &napiParam,
        size_t &convertArgc, bool &isPromise, AppExecFwk::FormInfoFilter &formInfoFilter);
    napi_value OnUpdateFormParseParam(napi_env env, size_t argc, napi_value* argv, int64_t &formId);
    napi_value OnOpenFormEditAbility(napi_env env, size_t argc, napi_value* argv);
    napi_value OnCloseFormEditAbility(napi_env env, size_t argc, napi_value* argv);
    napi_value OnRequestOverflow(napi_env env, size_t argc, napi_value* argv);
    napi_value OnCancelOverflow(napi_env env, size_t argc, napi_value* argv);
    napi_value OnActivateSceneAnimation(napi_env env, size_t argc, napi_value* argv);
    napi_value OnDeactivateSceneAnimation(napi_env env, size_t argc, napi_value* argv);
    napi_value OnUpdateTemplateFormDetailInfo(napi_env env, size_t argc, napi_value* argv);
    static bool ConvertFormOverflowInfo(napi_env env, napi_value argv, AppExecFwk::OverflowInfo* overflowInfo);
    static bool ConvertOverflowInfoArea(napi_env env, napi_value rangeArea, AppExecFwk::Rect &area);
    static bool GetAndConvertProperty(napi_env env, napi_value object, const char* propertyName, double& outValue);
    bool CheckCallerIsSystemApp();
    bool ConvertTemplateFormInfo(napi_env env, napi_value value,
        std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo);
    bool ConvertTemplateFormDetailInfo(napi_env env, napi_value value,
        AppExecFwk::TemplateFormDetailInfo &templateFormDetailInfo);
};

struct PublishFormCrossBundleControlParam {
    AppExecFwk::PublishFormCrossBundleInfo bundleInfo;
    bool isCanOpen = false;
};

class JsFormProviderProxyMgr : public AppExecFwk::FormProviderDelegateStub {
public:
    JsFormProviderProxyMgr() = default;

    virtual ~JsFormProviderProxyMgr() = default;

    static sptr<JsFormProviderProxyMgr> GetInstance();

    bool RegisterPublishFormCrossBundleControl(napi_env env, napi_ref callback);

    bool UnregisterPublishFormCrossBundleControl();
private:
    static std::mutex mutex_;
    static sptr<JsFormProviderProxyMgr> instance_;
    mutable std::mutex FormProviderProxyCallbackMutex_;

    DISALLOW_COPY_AND_MOVE(JsFormProviderProxyMgr);
    napi_ref crossBundleControlCallback_ = nullptr;
    napi_env crossBundleControlEnv_;
    mutable std::mutex crossBundleControlMutex_;
    ErrCode PublishFormCrossBundleControl(const AppExecFwk::PublishFormCrossBundleInfo &bundleInfo, bool &isCanOpen);
    void PublishFormCrossBundleControlInner(std::shared_ptr<PublishFormCrossBundleControlParam> dataParam);
    void ConvertParamToNapiValue(std::shared_ptr<PublishFormCrossBundleControlParam> dataParam, napi_value requestObj);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif /* OHOS_FORM_FWK_JS_FORM_PROVIDER_H */
