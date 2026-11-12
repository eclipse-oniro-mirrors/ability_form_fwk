/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_ipc_dispatch_table.h"

#include <initializer_list>

#include "bundle_constants.h"
#include "form_constants.h"
#include "form_ipc_handlers.h"
#include "form_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace {

// Policy factory core: derives checkCount and array indices from the step list.
constexpr FormPermissionPolicy MakePolicyFromSteps(const CheckType *steps, size_t stepCount)
{
    FormPermissionPolicy policy{};
    policy.checkCount = static_cast<uint8_t>(stepCount);
    for (size_t i = 0; i < stepCount; ++i) {
        policy.checks[i] = steps[i];
    }
    return policy;
}

// Row policy factory: the final deny code is assigned here (override, else GetDefaultDenyCode by permName).
constexpr FormPermissionPolicy MakePolicy(std::initializer_list<CheckType> steps = {},
                                          std::string_view permName = {}, ErrCode permDenyCode = 0)
{
    FormPermissionPolicy policy = MakePolicyFromSteps(steps.begin(), steps.size());
    policy.permName = permName;
    bool hasPermissionStep = false;
    for (uint8_t i = 0; i < policy.checkCount; ++i) {
        hasPermissionStep = hasPermissionStep || (policy.checks[i] == CheckType::Permission);
    }
    if (permDenyCode != 0) {
        policy.permDenyCode = permDenyCode;
    } else {
        policy.permDenyCode = hasPermissionStep ? GetDefaultDenyCode(permName) : 0;
    }
    return policy;
}

// Compile-time validators that check table invariants.
constexpr bool CheckStrictlyAscending(const HandlerEntry *entries, size_t entryCount)
{
    for (size_t i = 1; i < entryCount; ++i) {
        if (static_cast<uint32_t>(entries[i - 1].code) >= static_cast<uint32_t>(entries[i].code)) {
            return false;
        }
    }
    return true;
}

constexpr bool CheckSaBypassOnlyAtFirstPosition(const HandlerEntry *entries, size_t entryCount)
{
    for (size_t row = 0; row < entryCount; ++row) {
        const FormPermissionPolicy &policy = entries[row].policy;
        for (uint8_t i = FormPermissionPolicy::SA_BYPASS_STEP_COUNT; i < policy.checkCount; ++i) {
            if (policy.checks[i] == CheckType::SaBypass) {
                return false;
            }
        }
    }
    return true;
}

// The Permission step and a non-empty permName must appear together.
constexpr bool CheckPermissionMatchesPermName(const HandlerEntry *entries, size_t entryCount)
{
    for (size_t row = 0; row < entryCount; ++row) {
        const FormPermissionPolicy &policy = entries[row].policy;
        bool hasPermissionCheck = false;
        for (uint8_t i = 0; i < policy.checkCount; ++i) {
            hasPermissionCheck = hasPermissionCheck || (policy.checks[i] == CheckType::Permission);
        }
        if (hasPermissionCheck != !policy.permName.empty()) {
            return false;
        }
    }
    return true;
}

// Permission rows require a non-zero deny code; other rows stay zero (prevents silent allow).
constexpr bool CheckPermDenyApplicability(const HandlerEntry *entries, size_t entryCount)
{
    for (size_t row = 0; row < entryCount; ++row) {
        const FormPermissionPolicy &policy = entries[row].policy;
        bool hasPermissionCheck = false;
        for (uint8_t i = 0; i < policy.checkCount; ++i) {
            hasPermissionCheck = hasPermissionCheck || (policy.checks[i] == CheckType::Permission);
        }
        if (hasPermissionCheck != (policy.permDenyCode != 0)) {
            return false;
        }
    }
    return true;
}

// MAX_CHECK_COUNT needs no validator: oversized step lists fail constant evaluation.

}  // namespace

// Single definition point: one row per dispatched code, sorted for binary search; constexpr makes rows read-only.
constexpr HandlerEntry kEntries[] = {
    {IFormMgr::Message::FORM_MGR_ADD_FORM, FormIpcHandlers::HandleAddForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_DELETE_FORM, FormIpcHandlers::HandleDeleteForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORM, FormIpcHandlers::HandleUpdateForm, MakePolicy()},
    {IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE, FormIpcHandlers::HandleLifecycleUpdate,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REQUEST_FORM, FormIpcHandlers::HandleRequestForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_RELEASE_FORM, FormIpcHandlers::HandleReleaseForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM, FormIpcHandlers::HandleCastTempForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME,
        FormIpcHandlers::HandleSetNextRefreshTime,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE,
        FormIpcHandlers::HandleNotifyWhetherVisibleForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS, FormIpcHandlers::HandleDumpStorageFormInfos,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME,
        FormIpcHandlers::HandleDumpFormInfoByBundleName,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID, FormIpcHandlers::HandleDumpFormInfoByFormId,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID,
        FormIpcHandlers::HandleDumpFormTimerByFormId,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_MESSAGE_EVENT, FormIpcHandlers::HandleMessageEvent,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS, FormIpcHandlers::HandleDeleteInvalidForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE, FormIpcHandlers::HandleAcquireFormState,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE, FormIpcHandlers::HandleNotifyFormsVisible,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE,
        FormIpcHandlers::HandleNotifyFormsEnableUpdate,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO, FormIpcHandlers::HandleGetAllFormsInfo,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount})},
    {IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP, FormIpcHandlers::HandleGetFormsInfoByApp,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount})},
    {IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE,
        FormIpcHandlers::HandleGetFormsInfoByModule,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount})},
    {IFormMgr::Message::FORM_MGR_GET_FORMS_INFO,
        FormIpcHandlers::HandleGetFormsInfo, MakePolicy()},
    {IFormMgr::Message::FORM_MGR_ROUTER_EVENT, FormIpcHandlers::HandleRouterEvent,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM, FormIpcHandlers::HandleRequestPublishForm,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED,
        FormIpcHandlers::HandleIsRequestPublishFormSupported,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_SHARE_FORM, FormIpcHandlers::HandleShareForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE,
        FormIpcHandlers::HandleRecvFormShareInfoFromRemote,
        MakePolicy({CheckType::SaOnly})},
    {IFormMgr::Message::FORM_MGR_START_ABILITY, FormIpcHandlers::HandleStartAbility,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_START_ABILITIES_FROM_BACKGROUND)},
    {IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED,
        FormIpcHandlers::HandleNotifyFormsPrivacyProtected,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_CHECK_FMS_READY, FormIpcHandlers::HandleCheckFMSReady,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT, FormIpcHandlers::HandleBackgroundEvent,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_STOP_RENDERING_FORM, FormIpcHandlers::HandleStopRenderingForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE,
        FormIpcHandlers::HandleRegisterFormAddObserverByBundle,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE,
        FormIpcHandlers::HandleRegisterFormRemoveObserverByBundle,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_ACQUIRE_DATA, FormIpcHandlers::HandleAcquireFormData,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT, FormIpcHandlers::HandleGetFormsCount,
        MakePolicy({CheckType::SystemApp})},
    {IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT, FormIpcHandlers::HandleGetHostFormsCount,
        MakePolicy({CheckType::SystemApp})},
    {IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS,
        FormIpcHandlers::HandleGetRunningFormInfos,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE,
        FormIpcHandlers::HandleGetRunningFormInfosByBundleName,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER,
        FormIpcHandlers::HandleGetFormInstancesByFilter,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID,
        FormIpcHandlers::HandleGetFormInstanceById,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER,
        FormIpcHandlers::HandleRegisterAddObserver,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER,
        FormIpcHandlers::HandleRegisterRemoveObserver,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM, FormIpcHandlers::HandleUpdateProxyForm,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM,
        FormIpcHandlers::HandleRequestPublishProxyForm,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount})},
    {IFormMgr::Message::FORM_MGR_RELEASE_RENDERER, FormIpcHandlers::HandleReleaseRenderer,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR,
        FormIpcHandlers::HandleRegisterPublishFormInterceptor,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR,
        FormIpcHandlers::HandleUnregisterPublishFormInterceptor,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER,
        FormIpcHandlers::HandleRegisterClickCallbackEventObserver,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER,
        FormIpcHandlers::HandleUnregisterClickCallbackEventObserver,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_OBSERVE_FORM_RUNNING)},
    {IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY,
        FormIpcHandlers::HandleRegisterFormRouterProxy,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY,
        FormIpcHandlers::HandleUnregisterFormRouterProxy,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_SET_FORMS_RECYCLABLE, FormIpcHandlers::HandleSetFormsRecyclable,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_RECYCLE_FORMS, FormIpcHandlers::HandleRecycleForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_RECOVER_FORMS, FormIpcHandlers::HandleRecoverForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_HAS_FORM_VISIBLE_WITH_TOKENID,
        FormIpcHandlers::HandleHasFormVisible,
        MakePolicy({CheckType::SaOnly})},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORM_LOCATION, FormIpcHandlers::HandleUpdateFormLocation,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER,
        FormIpcHandlers::HandleGetFormsInfoByFilter,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount})},
    {IFormMgr::Message::FORM_MGR_CREATE_FORM, FormIpcHandlers::HandleCreateForm,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_PUBLISH_FORM_ERRCODE_RESULT,
        FormIpcHandlers::HandleSetPublishFormResult,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_ACQUIRE_ADD_FORM_RESULT,
        FormIpcHandlers::HandleAcquireAddFormResult,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_AGENT_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT,
        FormIpcHandlers::HandleRequestPublishFormWithSnapshot,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_BATCH_REFRESH_FORMS, FormIpcHandlers::HandleBatchRefreshForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_ENABLE_FORMS, FormIpcHandlers::HandleEnableForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_IS_SYSTEM_APP_FORM, FormIpcHandlers::HandleIsSystemAppForm,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_FORBIDDEN,
        FormIpcHandlers::HandleIsFormBundleForbidden,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORM_SIZE, FormIpcHandlers::HandleUpdateFormSize,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_LOCK_FORMS, FormIpcHandlers::HandleLockForms,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_PEOTECTED,
        FormIpcHandlers::HandleIsFormProtected,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_EXEMPT, FormIpcHandlers::HandleIsFormExempt,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_NOTIFY_FORM_LOCKED, FormIpcHandlers::HandleNotifyFormLocked,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_START_ABILITY_BY_FMS, FormIpcHandlers::HandleStartAbilityByFms,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_START_UI_ABILITY_BY_FMS,
        FormIpcHandlers::HandleStartUIAbilityByFms,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_START_ABILITY_BY_CROSS_BUNDLE,
        FormIpcHandlers::HandleStartAbilityByCrossBundle,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_PUBLISH_FORM_CROSS_BUNDLE)},
    {IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFOS,
        FormIpcHandlers::HandleGetPublishedFormInfos,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID,
        FormIpcHandlers::HandleGetPublishedFormInfoById,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_OPEN_FORM_EDIT_ABILITY,
        FormIpcHandlers::HandleOpenFormEditAbility,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_CLOSE_FORM_EDIT_ABILITY,
        FormIpcHandlers::HandleCloseFormEditAbility,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_REGISTER_OVERFLOW_PROXY,
        FormIpcHandlers::HandleRegisterOverflowProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_OVERFLOW_PROXY,
        FormIpcHandlers::HandleUnregisterOverflowProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_REQUEST_OVERFLOW, FormIpcHandlers::HandleRequestOverflow,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_REGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        FormIpcHandlers::HandleRegisterChangeSceneAnimationStateProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_CHANGE_SCENEANIMATION_STATE_PROXY,
        FormIpcHandlers::HandleUnregisterChangeSceneAnimationStateProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_CHANGE_SCENE_ANIMATION_STATE,
        FormIpcHandlers::HandleChangeSceneAnimationState,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_REGISTER_GET_FORM_RECT,
        FormIpcHandlers::HandleRegisterGetFormRectProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_GET_FORM_RECT,
        FormIpcHandlers::HandleUnregisterGetFormRectProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_GET_FORM_RECT,
        FormIpcHandlers::HandleGetFormRect, MakePolicy()},
    {IFormMgr::Message::FORM_MGR_NOTIFY_UPDATE_FORM_SIZE,
        FormIpcHandlers::HandleNotifyUpdateFormSize,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REGISTER_GET_LIVE_FORM_STATUS,
        FormIpcHandlers::HandleRegisterGetLiveFormStatusProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_GET_LIVE_FORM_STATUS,
        FormIpcHandlers::HandleUnregisterGetLiveFormStatusProxy,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_DEBUG_SIGNATURE,
        FormIpcHandlers::HandleIsFormDebugSignature,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_RELOAD_FORMS, FormIpcHandlers::HandleReloadForms, MakePolicy()},
    {IFormMgr::Message::FORM_MGR_RELOAD_ALL_FORMS, FormIpcHandlers::HandleReloadAllForms,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_IS_FORM_DUE_CONTROL, FormIpcHandlers::HandleIsFormDueControl,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_SEND_NON_TRANSPARENT_RATIO,
        FormIpcHandlers::HandleSendNonTransparencyRatio,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_GET_ALL_TEMPLATE_FORMS_INFO,
        FormIpcHandlers::HandleGetAllTemplateFormsInfo,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount, CheckType::Permission},
                   Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_GET_TEMPLATE_FORMS_INFO_BY_APP,
        FormIpcHandlers::HandleGetTemplateFormsInfoByApp,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount, CheckType::Permission},
                   Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_GET_TEMPLATE_FORMS_INFO_BY_MODULE,
        FormIpcHandlers::HandleGetTemplateFormsInfoByModule,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount, CheckType::Permission},
                   Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_CROSS_BUNDLE_CONTROL,
        FormIpcHandlers::HandleRegisterPublishFormCrossBundleControl,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission},
                   Constants::PERMISSION_PUBLISH_FORM_CROSS_BUNDLE_CONTROL)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_CROSS_BUNDLE_CONTROL,
        FormIpcHandlers::HandleUnregisterPublishFormCrossBundleControl,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission},
                   Constants::PERMISSION_PUBLISH_FORM_CROSS_BUNDLE_CONTROL)},
    {IFormMgr::Message::FORM_MGR_REGISTER_TEMPLATE_FORM_DETAIL_INFO_CHANGE,
        FormIpcHandlers::HandleRegisterTemplateFormDetailInfoChange,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount, CheckType::Permission},
                   Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_TEMPLATE_FORM_DETAIL_INFO_CHANGE,
        FormIpcHandlers::HandleUnregisterTemplateFormDetailInfoChange,
        MakePolicy({CheckType::SystemCaller, CheckType::CrossAccount, CheckType::Permission},
                   Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UPDATE_TEMPLATE_FORM_DETAIL_INFO,
        FormIpcHandlers::HandleUpdateTemplateFormDetailInfo,
        MakePolicy({CheckType::SystemCaller})},
    {IFormMgr::Message::FORM_MGR_GET_FORMIDS_BY_FORM_LOCATION,
        FormIpcHandlers::HandleGetFormIdsByFormLocation,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_CROSS_USER,
        FormIpcHandlers::HandleRequestPublishFormCrossUser,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_AGENT_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REGISTER_FORM_WANT_CALLBACK,
        FormIpcHandlers::HandleRegisterFormWantCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_WANT_CALLBACK,
        FormIpcHandlers::HandleUnregisterFormWantCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_REGISTER_UPDATE_FORMS_CONFIG_CALLBACK,
        FormIpcHandlers::HandleRegisterUpdateFormsConfigCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_UPDATE_FORMS_CONFIG_CALLBACK,
        FormIpcHandlers::HandleUnregisterUpdateFormsConfigCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORMS_CONFIG, FormIpcHandlers::HandleUpdateFormsConfig,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_FORM_CUSTOM_CONFIG)},
    {IFormMgr::Message::FORM_MGR_REGISTER_DELETE_FORMS_CALLBACK,
        FormIpcHandlers::HandleRegisterDeleteFormsCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_DELETE_FORMS_CALLBACK,
        FormIpcHandlers::HandleUnregisterDeleteFormsCallback,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_DELETE_FORMS, FormIpcHandlers::HandleDeleteForms,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_FORM_CUSTOM_CONFIG)},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORM_CROSS_BUNDLE,
        FormIpcHandlers::HandleUpdateFormCrossBundle,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_UPDATE_FORM_CROSS_BUNDLE)},
    {IFormMgr::Message::FORM_MGR_REGISTER_FORM_HOST_SERVICE,
        FormIpcHandlers::HandleRegisterFormHostService,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_HOST_SERVICE,
        FormIpcHandlers::HandleUnregisterFormHostService,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_GET_AVAILABLE_FORM_HOST_SERVICES,
        FormIpcHandlers::HandleGetAvailableFormHostServices,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_AGENT_REQUIRE_FORM,
                   ERR_APPEXECFWK_FORM_PERMISSION_DENY_AGENT_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_CROSS_DEVICE,
        FormIpcHandlers::HandleRequestPublishFormCrossDevice,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_AGENT_REQUIRE_FORM,
                   ERR_APPEXECFWK_FORM_PERMISSION_DENY_AGENT_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_INSIGHT_INTENT_EVENT, FormIpcHandlers::HandleInsightIntentEvent,
        MakePolicy({CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount},
                   Constants::PERMISSION_REQUIRE_FORM)},
    {IFormMgr::Message::FORM_MGR_UPDATE_FORM_PROVIDER_INFO,
        FormIpcHandlers::HandleUpdateFormProviderInfo,
        MakePolicy()},
    {IFormMgr::Message::FORM_MGR_REGISTER_GET_VISIBLE_FORM_RECT_PROXY,
        FormIpcHandlers::HandleRegisterGetVisibleFormRectProxy,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_UNREGISTER_GET_VISIBLE_FORM_RECT_PROXY,
        FormIpcHandlers::HandleUnregisterGetVisibleFormRectProxy,
        MakePolicy({CheckType::SystemCaller, CheckType::Permission}, Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)},
    {IFormMgr::Message::FORM_MGR_GET_VISIBLE_FORM_RECT,
        FormIpcHandlers::HandleGetVisibleFormRect,
        MakePolicy({CheckType::SystemCaller})},
};

constexpr size_t ENTRY_COUNT = sizeof(kEntries) / sizeof(kEntries[0]);

// Half-open span halving divisor for binary search.
constexpr size_t BINARY_SEARCH_HALF = 2;

// First-code sentinel: dispatched codes are append-only; gaps are reserved codes reconciled by unit test.
constexpr uint32_t FIRST_DISPATCHED_CODE = 3001u;  // FORM_MGR_ADD_FORM
static_assert(static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM) == FIRST_DISPATCHED_CODE,
    "first message code drifted");
static_assert(CheckStrictlyAscending(kEntries, ENTRY_COUNT), "IPC codes must be strictly ascending");
static_assert(CheckSaBypassOnlyAtFirstPosition(kEntries, ENTRY_COUNT), "SA caller exemption must be checks[0]");
static_assert(CheckPermissionMatchesPermName(kEntries, ENTRY_COUNT), "Permission step and permName mismatch");
static_assert(CheckPermDenyApplicability(kEntries, ENTRY_COUNT), "permDenyCode applicability broken");

FormIpcDispatchTable::FormIpcDispatchTable()
    : checker_(std::make_shared<FailClosedChecker>())
{}

const HandlerEntry *FormIpcDispatchTable::Find(uint32_t code) const
{
    size_t low = 0;
    size_t high = ENTRY_COUNT;
    while (low < high) {
        size_t middle = low + (high - low) / BINARY_SEARCH_HALF;
        uint32_t midCode = static_cast<uint32_t>(kEntries[middle].code);
        if (midCode < code) {
            low = middle + 1;
        } else if (midCode > code) {
            high = middle;
        } else {
            return &kEntries[middle];
        }
    }
    return nullptr;
}

const HandlerEntry *FormIpcDispatchTable::GetEntries() const
{
    return kEntries;
}

size_t FormIpcDispatchTable::GetEntryCount() const
{
    return ENTRY_COUNT;
}

FormIpcDispatchTable &FormIpcDispatchTable::GetInstance()
{
    static FormIpcDispatchTable instance;
    return instance;
}

void FormIpcDispatchTable::SetAccessChecker(std::shared_ptr<IStubAccessChecker> checker)
{
    checker_ = std::move(checker);
}

std::shared_ptr<IStubAccessChecker> FormIpcDispatchTable::GetAccessChecker() const
{
    return checker_;
}

}  // namespace AppExecFwk
}  // namespace OHOS
