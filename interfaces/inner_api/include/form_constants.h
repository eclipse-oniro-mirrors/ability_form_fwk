/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_CONSTANTS_H
#define OHOS_FORM_FWK_FORM_CONSTANTS_H

#include <map>
#include <string>

namespace OHOS {
namespace AppExecFwk {
namespace FormConstants {
    constexpr int32_t FOUNDATION_UID = 5523;
}
namespace Constants {
    constexpr const char* PERMISSION_INTERACT_ACROSS_LOCAL_ACCOUNTS = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
    constexpr const char* PERMISSION_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
    constexpr const char* PERMISSION_AGENT_REQUIRE_FORM = "ohos.permission.AGENT_REQUIRE_FORM";
    constexpr const char* PERMISSION_KEEP_BACKGROUND_RUNNING = "ohos.permission.KEEP_BACKGROUND_RUNNING";
    constexpr const char* PERMISSION_OBSERVE_FORM_RUNNING = "ohos.permission.OBSERVE_FORM_RUNNING";
    constexpr const char* PERMISSION_START_ABILITIES_FROM_BACKGROUND =
        "ohos.permission.START_ABILITIES_FROM_BACKGROUND";
    constexpr const char* PERMISSION_PUBLISH_FORM_CROSS_BUNDLE = "ohos.permission.PUBLISH_FORM_CROSS_BUNDLE";
    constexpr const char* PARAM_FORM_IDENTITY_KEY = "ohos.extra.param.key.form_identity";
    constexpr const char* PARAM_FORM_CALLING_IDENTITY_KEY = "ohos.extra.param.key.form_calling_identity";
    constexpr const char* PARAM_MODULE_NAME_KEY = "ohos.extra.param.key.module_name";
    constexpr const char* PARAM_BUNDLE_NAME_KEY = "ohos.extra.param.key.bundle_name";
    constexpr const char* PARAM_ABILITY_NAME_KEY = "ohos.extra.param.key.ability_name";
    constexpr const char* PARAM_FORM_NAME_KEY = "ohos.extra.param.key.form_name";
    constexpr const char* PARAM_FORM_DIMENSION_KEY = "ohos.extra.param.key.form_dimension";
    constexpr const char* PARAM_FORM_RENDERINGMODE_KEY = "ohos.extra.param.key.form_rendering_mode";
    constexpr const char* PARAM_FORM_OBSCURED_KEY = "ohos.extra.param.key.form_obscured_mode";
    constexpr const char* PARAM_MESSAGE_KEY = "ohos.extra.param.key.message";
    constexpr const char* PARAM_FORM_TEMPORARY_KEY = "ohos.extra.param.key.form_temporary";
    constexpr const char* PARAM_CALLER_BUNDLE_NAME_KEY = "ohos.extra.param.key.caller_bundle_name";
    constexpr const char* PARAM_FORM_TRANSPARENCY_KEY = "ohos.extra.param.key.form_background_transparency";
    constexpr const char* PARAM_FORM_WIDTH_KEY = "ohos.extra.param.key.form_width";
    constexpr const char* PARAM_FORM_HEIGHT_KEY = "ohos.extra.param.key.form_height";
    constexpr const char* PARAM_LAYOUT_WIDTH_KEY = "ohos.extra.param.key.layout_width";
    constexpr const char* PARAM_LAYOUT_HEIGHT_KEY = "ohos.extra.param.key.layout_height";
    constexpr const char* PARAM_FORM_VIEW_SCALE = "ohos.extra.param.key.form_view_scale";
    constexpr const char* PARAM_JSON_WANT_KEY = "ohos.extra.param.key.json_want";
    constexpr const char* PARAM_LIVE_FORM_ID_KEY = "ohos.extra.param.key.live_form_id";
    constexpr int32_t ONE_HOST_MAX_FORM_SIZE = 256;
    constexpr const char* RECREATE_FORM_KEY = "ohos.extra.param.key.recreate";
    constexpr const char* PARAM_FORM_CUSTOMIZE_KEY = "ohos.extra.param.key.form_customize";
    constexpr const char* PARAM_FORM_ORIENTATION_KEY = "ohos.extra.param.key.form_orientation";
    constexpr int32_t ORIENTATION_PORTRAIT = 1;
    constexpr int32_t ORIENTATION_LANDSCAPE = 2;
    constexpr const char* PARAM_FORM_ABILITY_NAME_KEY = "abilityName";
    constexpr const char* PARAM_FORM_USER_ID = "ohos.extra.param.key.form_user_id";
    constexpr const char* KEY_IS_TIMER = "isCountTimerRefresh";
    constexpr const char* KEY_TIMER_REFRESH = "isTimerRefresh";
    constexpr const char* KEY_CONNECT_REFRESH = "isConnectRefresh";
    constexpr const char* PARAM_FORM_REFRESH_TYPE = "ohos.extra.param.key.refresh_type";
    constexpr const char* SYSTEM_PARAM_FORM_UPDATE_TIME = "persist.sys.fms.form.update.time";
    constexpr const char* SYSTEM_PARAM_FORM_REFRESH_MIN_TIME = "persist.sys.fms.form.refresh.min.time";
    constexpr const char* ACTION_UPDATEATTIMER = "form_update_at_timer";
    constexpr const char* KEY_WAKEUP_TIME = "wakeUpTime";
    constexpr const char* KEY_WAKEUP_TIME_LEFT = "wakeUpTimeLeft";
    constexpr const char* KEY_WAKEUP_TIME_RIGHT = "wakeUpTimeRight";
    constexpr const char* KEY_ACTION_TYPE = "form_update_action_type";
    constexpr const char* ABS_CODE_PATH = "/data/app/el1/bundle/public";
    constexpr const char* LOCAL_CODE_PATH = "/data/storage/el1/bundle";
    constexpr const char* LOCAL_BUNDLES = "/data/bundles";
    constexpr const char* FORM_PUBLISH_ACTION = "action.form.publish";
    constexpr const char* FORM_PAGE_ACTION = "action.form.page";
    constexpr const char* OPEN_FORM_MANAGE_VIEW  = "openFormManageView";
    constexpr int32_t PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE = 1;
    constexpr int32_t PAGE_ROUTER_SERVICE_CODE_CONTROL_CENTER = 2;
    constexpr int32_t PAGE_ROUTER_SERVICE_CODE_FORM_EDIT = 3;
    constexpr int32_t PAGE_ROUTER_SERVICE_CODE_LIVE_FORM = 4;
    constexpr const char* PARMA_REQUEST_METHOD = "requestMethod";
    constexpr const char* PARAM_OPEN_FORM_EDIT_VIEW = "openFormEditView";
    constexpr const char* PARAM_OPEN_FORM_EDIT_SEC_PAGE_VIEW = "openFormEditSecPageView";
    constexpr const char* PARAM_PAGE_ROUTER_SERVICE_CODE = "pageRouterServiceCode";
    constexpr const char* PARAM_SEC_PAGE_ABILITY_NAME = "secPageAbilityName";
    constexpr const char* PARAM_DEVICE_ID_KEY = "ohos.extra.param.key.device_id";
    constexpr const char* PARAM_FORM_HOST_TOKEN = "ohos.extra.param.form.host.token";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_BUNDLE_KEY = "ohos.extra.param.key.form_host_bundle_name";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_MODULE_KEY = "ohos.extra.param.key.form_host_module_name";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_ABILITY_KEY = "ohos.extra.param.key.form_host_ability_name";
    constexpr const char* FRS_BUNDLE_NAME = "com.ohos.formrenderservice";
    constexpr const char* FRS_APP_INDEX = "ohos.extra.param.key.frs_index";
    constexpr const char* PARAM_FORM_ID = "formID";
    constexpr const char* IS_FORM_AGENT = "isFormAgent";
    constexpr const char* PARAM_FORM_BORDER_WIDTH_KEY = "ohos.extra.param.key.form_border_width";
    constexpr const char* FORM_LOCATION_KEY = "ohos.extra.param.key.form_location";
    constexpr const char* FORM_WIDTH_VP_KEY = "ohos.extra.param.key.form_width_vp";
    constexpr const char* FORM_HEIGHT_VP_KEY = "ohos.extra.param.key.form_height_vp";
    constexpr const char* FORM_DISABLE_GESTURE_KEY = "ohos.extra.param.key.form_disable_gesture";
    constexpr const char* FORM_DISABLE_BLUR_BACKGROUND = "ohos.extra.param.key.form_disable_blur_background";
    constexpr int32_t TYPE_RESET_LIMIT = 1;
    constexpr int32_t TYPE_STATIC_UPDATE = 2;
    constexpr int32_t TYPE_DYNAMIC_UPDATE = 3;
    const long ABS_REFRESH_MS = 2500;
    constexpr const char* PARAM_HOST_BG_INVERSE_COLOR_KEY = "ohos.extra.param.key.host_bg_inverse_color";
    constexpr const char* PARAM_FONT_FOLLOW_SYSTEM_KEY = "ohos.inner.key.font_follow_system";
    constexpr const char* PARAM_FORM_ENABLE_BLUR_BACKGROUND_KEY = "ohos.inner.key.enable_blur_background";
    constexpr const char* PARAM_THEME_KEY  = "ohos.extra.param.key.form_is_theme";
    constexpr const char* PARAM_THEME_THEME_FORM_ID  = "themeFormId";
    constexpr const char* PARAM_THEME_THEME_ID  = "themeId";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY = "ohos.extra.param.key.add_form_to_host_snapshot";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_WIDTH_KEY = "ohos.extra.param.key.add_form_to_host_width";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY = "ohos.extra.param.key.add_form_to_host_height";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_SCREENX_KEY = "ohos.extra.param.key.add_form_to_host_screenx";
    constexpr const char* PARAM_PUBLISH_FORM_HOST_SCREENY_KEY = "ohos.extra.param.key.add_form_to_host_screeny";
    constexpr const char* CPU_SCENE_ID_CONFIG_UPDATE  = "1";
    constexpr const char* PARAM_DYNAMIC_NAME_KEY = "isDynamic";
    constexpr const char* RECYCLE_FORMS_USER_ID = "ohos.extra.param.key.recycle_forms_user_id";
    constexpr const char* PARAM_APP_CLONE_INDEX_KEY = "ohos.extra.param.key.appCloneIndex";
    constexpr const char* PARAM_GAME_CARD_SUPPORT_KEY = "persist.sceneboard.desktop.game_card";
    constexpr const char* PARAM_LIVE_FORM_SUPPORT_KEY = "persist.sys.fms.support.liveForm";
    constexpr const char* PARAM_GAME_CARD_KEY = "gameType";
    constexpr const char* PARAM_GAME_CARD_TYPE = "quick";
    // live form support type
    constexpr const char* LIVE_FORM_NONE = "0";
    constexpr const char* FUN_INTERACTION = "1";
    constexpr const char* SCENE_ANIMATION = "2";
    constexpr const char* LIVE_FORM_BOTH = "3";

    // class names
    constexpr const char* FORM_INFO_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormInfo";
    constexpr const char* FORM_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.formInfoInner";
    constexpr const char* RUNNING_FORM_INFO_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.RunningFormInfo";
    constexpr const char* RUNNING_FORM_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.runningFormInfoInner";
    constexpr const char* FORM_BINDING_DATA_CLASS_NAME =
        "@ohos.app.form.formBindingData.formBindingData.FormBindingData";
    constexpr const char* ASYNC_CALLBACK_WRAPPER_CLASS_NAME = "@ohos.app.form.formHost.AsyncCallbackWrapper";
    constexpr const char* CALLBACK_WRAPPER_CLASS_NAME = "@ohos.app.form.formHost.CallbackWrapper";
    constexpr const char* FORM_STATE_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormStateInfoInner";
    constexpr const char* FORM_STATE_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormState";
    constexpr const char* FUNINTERACTION_PARAMS_INNER_CLASS_NAME =
        "@ohos.app.form.formInfo.formInfo.FunInteractionParamsInner";
    constexpr const char* SCENE_ANIMATION_PARAMS_INNER_CLASS_NAME =
        "@ohos.app.form.formInfo.formInfo.SceneAnimationParamsInner";


    constexpr int32_t UNKNOWN = 0;
    // The form events type which means that the form becomes visible.
    constexpr int32_t FORM_VISIBLE = 1;
    // The form events type which means that the form becomes invisible.
    constexpr int32_t FORM_INVISIBLE = 2;

    // The default user id
    constexpr int32_t DEFAULT_USER_ID = 0;

    constexpr int32_t DEFAULT_SANDBOX_FRS_APP_INDEX = 1001;

    // The invalid user id
    constexpr int32_t INVALID_USER_ID = -1;

    // The default provider user id
    constexpr int32_t DEFAULT_PROVIDER_USER_ID = -1;

    // The max uid of system app.
    constexpr int32_t MAX_SYSTEM_APP_UID = 10000;

    constexpr int32_t CALLING_UID_TRANSFORM_DIVISOR = 200000;

    constexpr int32_t MIN_TIME_SPEED = 1;
    constexpr int32_t MAX_TIME_SPEED = 1000;
    constexpr int32_t MAX_HOUR = 23;
    constexpr int32_t MAX_MINUTE = 59;
    constexpr int32_t MAX_SECOND = 60;
    constexpr int32_t MIN_TIME = 0;
    constexpr int32_t HOUR_PER_DAY = 24;
    constexpr int32_t MIN_PER_HOUR = 60;
    constexpr int32_t SEC_PER_MIN = 60;
    constexpr int32_t MS_PER_DAY = 24 * 60 * 60 * 1000;
    const long TIME_1000 = 1000;
    const long TIME_1000000 = 1000000;
    const long TIME_CONVERSION = 30 * 60 * TIME_1000;
    constexpr int32_t MIN_CONFIG_DURATION = 1; // 1 means 30 min
    constexpr int32_t MAX_CONFIG_DURATION = 2 * 24 * 7; // one week
    const long MIN_PERIOD = MIN_CONFIG_DURATION * TIME_CONVERSION; // 30 min in ms unit
    const long MAX_PERIOD = MAX_CONFIG_DURATION * TIME_CONVERSION; // 1 week in ms unit
    const long ABS_TIME = 30 * TIME_1000; // 30s abs time
    constexpr const char* TIME_DELIMETER = ":";
    constexpr const char* TIMES_DELIMETER = ",";
    constexpr int32_t UPDATE_AT_CONFIG_COUNT = 2;
    constexpr int32_t UPDATE_AT_CONFIG_MAX_COUNT = 24;

    constexpr int32_t LIMIT_COUNT = 50;
    constexpr int32_t MIN_NEXT_TIME = 300; // seconds

    // The max retry times of reconnection.
    constexpr int32_t MAX_RETRY_TIME = 30;
    // The time interval between reconnections(milliseconds).
    constexpr int32_t SLEEP_TIME = 1000;

    constexpr int64_t MS_PER_SECOND = 1000;

    // form host bundlename
    constexpr const char* PARAM_FORM_HOST_BUNDLENAME_KEY = "form_host_bundlename";

    // form manager service bundlename
    constexpr const char* PARAM_FORM_MANAGER_SERVICE_BUNDLENAME_KEY = "form_manager_service_bundlename";

    // PROVIDER_FLAG false:ProviderFormInfo is null;true: ProviderFormInfo not null
    constexpr const char* PROVIDER_FLAG = "provider_flag";
    constexpr const char* FORM_CONNECT_ID = "form_connect_id";
    constexpr const char* FORM_SUPPLY_INFO = "form_supply_info";
    constexpr const char* FORM_SHARE_REQUEST_CODE = "form_share_request_code";
    constexpr const char* FORM_ACQUIRE_DATA_REQUEST_CODE = "form_acquire_data_request_code";
    // the delimiter between bundleName and abilityName
    constexpr const char* NAME_DELIMITER = "::";

    constexpr const char* PARAM_FORM_ADD_COUNT = "form.add.count";

    constexpr const char* FORM_SUPPLY_UID = "form_supply_uid";
    constexpr const char* FORM_RENDER_COMP_ID = "form_render_comp_id";
    constexpr const char* FORM_DELAY_TIME_OF_RECYCLE = "form_delay_time_of_recycle";
    constexpr const char* FORM_STATUS_DATA = "form_status_data";
    constexpr const char* FORM_IS_DYNAMIC = "form_is_dynamic";
    constexpr const char* FORM_IS_RECOVER_FORM = "form_is_recover_form";
    constexpr const char* FORM_IS_STATIC_FORM_UPDATE_SIZE = "form_is_static_form_update_size";
    constexpr const char* FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT = "form_is_recover_form_to_handle_click_event";
    constexpr const char* FORM_STATUS_EVENT = "form_status_event";
    constexpr const char* FORM_STATUS_EVENT_ID = "form_status_event_id";

    const size_t MAX_LAYOUT = 8;
    constexpr int32_t MAX_FORMS = 512;
    constexpr int32_t MAX_RECORD_PER_APP = 256;
    constexpr int32_t MAX_TEMP_FORMS = 256;
    constexpr int32_t MAX_FORM_DATA_SIZE = 1024;
    constexpr int32_t DEFAULT_VISIBLE_NOTIFY_DELAY = 1000;

    constexpr char MAX_NORMAL_FORM_SIZE [] = "maxNormalFormSize";
    constexpr char MAX_TEMP_FORM_SIZE [] = "maxTempFormSize";
    constexpr char HOST_MAX_FORM_SIZE [] = "hostMaxFormSize";
    constexpr char VISIBLE_NOTIFY_DELAY [] = "visibleNotifyDelayTime";

    constexpr int32_t NOT_IN_RECOVERY = 0;
    constexpr int32_t RECOVER_FAIL = 1;
    constexpr int32_t IN_RECOVERING = 2;

    constexpr int32_t FLAG_HAS_OBJECT = 1;
    constexpr int32_t FLAG_NO_OBJECT = 0;

    constexpr int32_t DEATH_RECIPIENT_FLAG = 0;
    constexpr int32_t MAX_VISIBLE_NOTIFY_LIST = 32;

    constexpr const char* ACQUIRE_TYPE = "form_acquire_form";
    constexpr int32_t ACQUIRE_TYPE_CREATE_FORM = 1;
    constexpr int32_t ACQUIRE_TYPE_RECREATE_FORM = 2;

    constexpr int32_t DELETE_FORM = 3;
    constexpr int32_t RELEASE_FORM = 8;
    constexpr int32_t RELEASE_CACHED_FORM = 9;

    constexpr int64_t INVALID_UDID_HASH = 0L;

    constexpr int32_t REFRESH_ALL_FORM = 0;
    constexpr int32_t REFRESH_APP_FORM = 1;
    constexpr int32_t REFRESH_ATOMIC_FORM = 2;
    constexpr int32_t REFRESH_SYSTEMAPP_FORM = 3;

    enum class Dimension : int8_t {
        DIMENSION_MIN = 1,
        DIMENSION_1_2 = DIMENSION_MIN,
        DIMENSION_2_2,
        DIMENSION_2_4,
        DIMENSION_4_4,
        DIMENSION_2_1,
        DIMENSION_1_1,
        DIMENSION_6_4,
        DIMENSION_2_3,
        DIMENSION_3_3,
        DIMENSION_MAX = DIMENSION_3_3
    };

    enum class Shape : int8_t {
        RECT = 1,
        CIRCLE
    };

    const std::map<Dimension, std::string> DIMENSION_MAP = {
        {Dimension::DIMENSION_1_2, "1*2"},
        {Dimension::DIMENSION_2_2, "2*2"},
        {Dimension::DIMENSION_2_4, "2*4"},
        {Dimension::DIMENSION_4_4, "4*4"},
        {Dimension::DIMENSION_2_1, "2*1"},
        {Dimension::DIMENSION_1_1, "1*1"},
        {Dimension::DIMENSION_6_4, "6*4"},
        {Dimension::DIMENSION_2_3, "2*3"},
        {Dimension::DIMENSION_3_3, "3*3"}
    };

    struct StatusInfo {
        std::string activeState;
        bool isSupportLauncher;
    };

    const std::map<std::string, StatusInfo> LIVE_FORM_STATUS_MAP = {
        {"00", {"INACTIVE", false}},
        {"01", {"INACTIVE", true}},
        {"10", {"PAUSE", false}},
        {"11", {"PAUSE", true}},
        {"20", {"ACTIVE", false}},
        {"21", {"ACTIVE", true}},
    };

    enum class RenderingMode : int8_t {
        FULL_COLOR = 0,
        SINGLE_COLOR
    };

    enum class FormLocation : int8_t {
        OTHER = -1,
        DESKTOP = 0,
        FORM_CENTER = 1,
        FORM_MANAGER = 2,
        NEGATIVE_SCREEN = 3,
        FORM_CENTER_NEGATIVE_SCREEN = 4,
        FORM_MANAGER_NEGATIVE_SCREEN = 5,
        SCREEN_LOCK = 6,
        AI_SUGGESTION = 7,
    };

    enum class PublishFormErrorCode : int8_t {
        SUCCESS,
        NO_SPACE,
        PARAM_ERROR,
        INTERNAL_ERROR,
    };

    struct PublishFormResult {
        PublishFormErrorCode code;
        std::string message;
    };
    // refresh type
    constexpr int32_t REFRESHTYPE_DEFAULT = -1;
    constexpr int32_t REFRESHTYPE_HOST = 0;
    constexpr int32_t REFRESHTYPE_INTERVAL = 1;
    constexpr int32_t REFRESHTYPE_UPDATETIMES = 2;
    constexpr int32_t REFRESHTYPE_UPDATENEXTTIME = 3;
    constexpr int32_t REFRESHTYPE_NETWORKCHANGED = 4;
    constexpr int32_t REFRESHTYPE_VISIABLE = 99;
    constexpr int32_t FULL_UPDATE = 0;
    constexpr int32_t ADD_UPDATE = 1;

    // rdb
    const std::string FORM_MANAGER_SERVICE_PATH = "/data/service/el1/public/database/form_storage";
    const std::string FORM_RDB_NAME = "/formdb.db";
    constexpr const char* FORM_RDB_TABLE_NAME = "form_table";
    constexpr const char* FORM_JOURNAL_MODE = "WAL";
    constexpr const char* FORM_SYNC_MODE = "FULL";
    constexpr int32_t FORM_RDB_VERSION = 1;
    constexpr const char* FORM_RDB_FILE_TYPE = "";
    constexpr const char* FORM_RENDER_TYPE_KEY = "form_render_type";
    constexpr int32_t RENDER_FORM = 0; // default value
    constexpr int32_t UPDATE_RENDERING_FORM = 1;
    constexpr const char* FORM_UPDATE_TYPE_KEY = "form_update_type";
    constexpr int32_t ADD_FORM_UPDATE_FORM = 0; // default value
    constexpr int32_t ADAPTER_UPDATE_FORM = 1;
    constexpr const char* FORM_COMPILE_MODE_KEY = "form_compile_mode";
    constexpr const char* FORM_COMPATIBLE_VERSION_KEY = "form_compatible_version";
    constexpr const char* FORM_TARGET_VERSION_KEY = "form_target_version";

    //ArkTs card
    constexpr const char* FORM_COMP_ID = "ohos.extra.param.key.form_comp_id";
    constexpr const char* FORM_DENSITY = "ohos.extra.param.key.form_density";
    constexpr const char* FORM_PROCESS_ON_ADD_SURFACE = "ohos.extra.param.key.process_on_add_surface";
    constexpr const char* FORM_ALLOW_UPDATE = "allowUpdate";

    // The state of whether the ArkTs card can be rendered
    constexpr const char FORM_RENDER_STATE[] = "ohos.extra.param.key.form_render_state";
    // The state of whether the ArkTs card can be rendered without being unlocked
    constexpr const char FORM_RENDER_WITHOUT_UNLOCK_STATE[] = "ohos.extra.param.key.form_render_without_unlock_state";

    //CallEvent
    constexpr const char* FORM_CALL_EVENT_PARAMS = "params";
    constexpr const char* PARAM_FORM_CALL_EVENT_METHOD_KEY = "method";
    constexpr int32_t EVENT_CALL_NOTIFY = 1;
    //arquireFormData
    constexpr const char* LAUNCH_REASON_KEY = "ohos.extra.param.key.form_launch_reason";
    // The form launch reason which means that the form is default.
    constexpr int32_t FORM_DEFAULT = 1;
    // The form launch reason which means that the form is share.
    constexpr int32_t FORM_SHARE = 2;
    // Specify the form Id
    constexpr const char* PARAM_FORM_MIGRATE_FORM_KEY = "ohos.extra.param.key.migrate_form";
    // For click message event
    constexpr const char* KEY_DIRECT_CALL_INAPP = "directCallInApp";
    // Is the user granted
    constexpr const char* FORM_PERMISSION_GRANTED_KEY = "ohos.extra.param.key.permission_granted";
    // User permission name
    constexpr const char* FORM_PERMISSION_NAME_KEY = "ohos.extra.param.key.permission_name";

    constexpr const char* MODULE_PKG_NAME_KEY = "pkg_name";
    constexpr const char* MODULE_HAP_PATH_KEY = "hap_path";
    // Form enable skeleton key
    constexpr const char* FORM_ENABLE_SKELETON_KEY = "ohos.extra.param.key.enable_skeleton";
    // Allow form update and refresh
    constexpr const char* FORM_ENABLE_UPDATE_REFRESH_KEY = "enableFormUpdateRefresh";
    // Is form contains multiple app
    const std::string IS_MULTI_APP_FORM = "isMultiAppForm";
    // form contains multi app is true
    const std::string IS_MULTI_APP_FORM_TRUE = "true";
    // Form data update type
    constexpr const char* FORM_DATA_UPDATE_TYPE = "formDataUpdateType";
    // Form info max num
    constexpr const int32_t FORM_INFO_MAX_NUM = 16;
    // Form version code
    constexpr const int32_t FORM_VERSION_CODE = 100002;
    // Form domain id
    constexpr uint64_t FORM_DOMAIN_ID = 0xD001301;
    // Is form need the addition process on request form
    constexpr const char* IS_NEED_ADDFORM_ON_REQUEST = "isNeedAddForm";

    const std::string FORM_MGR_CONFIG_DIR = "/data/service/el1/public/update/param_service/install/system/etc/FormMgrConfig/";

    const std::string VERSION_FILE_NAME = "version.txt";

    constexpr const char* FMC_DEFAULT_VERSION = "10.10.25.100";
    constexpr const char* FORM_IS_VISIBLE = "ohos.extra.param.key.form_is_visible";

    constexpr int64_t DETECT_FORM_EXIT_DELAY_TASK = 30000; // task type base
    constexpr int64_t DETECT_FORM_EXIT_TIMEOUT_DELAY = 10 * 1000;

    constexpr int32_t DUE_INVALID_UPDATE_DURATION = -1;

    constexpr char DISTRIBUTE_FORM_MODULE[] = "widgetUiModule";
}  // namespace Constants
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_CONSTANTS_H
