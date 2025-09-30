/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FMS_LOG_WRAPPER_H
#define OHOS_FORM_FWK_FMS_LOG_WRAPPER_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG
#include <cinttypes>
#include <functional>

#include <string>

#include "hilog/log.h"

namespace OHOS::AAFwk {
static const std::unordered_map<std::string, std::string> fileNameMap_ = {
    {"form_ashmem", "FA"},
    {"form_ecological_rule_param", "FERP"},
    {"form_event_hiappevent", "FEH"},
    {"form_file_util", "FFU"},
    {"form_host_proxy", "FHP"},
    {"form_host_stub", "FHS"},
    {"form_info_filter", "FIF"},
    {"form_instance", "FI"},
    {"form_instances_filter", "FIF"},
    {"form_js_info", "FJI"},
    {"form_lock_info", "FLI"},
    {"form_mgr_proxy", "FMP"},
    {"form_mgr_stub", "FMS"},
    {"form_provider_data", "FPD"},
    {"form_provider_info", "FPI"},
    {"form_provider_proxy", "FPP"},
    {"form_provider_stub", "FPS"},
    {"form_publish_interceptor_proxy", "FPIP"},
    {"form_publish_interceptor_stub", "FPIS"},
    {"form_render_proxy", "FRP"},
    {"form_render_stub", "FRS"},
    {"form_share_info", "FSI"},
    {"form_status_print", "FSP"},
    {"form_supply_proxy", "FSP"},
    {"form_supply_stub", "FSS"},
    {"form_surface_info", "FSI"},
    {"js_form_state_observer_proxy", "JFSOP"},
    {"js_form_state_observer_stub", "JFSOS"},
    {"provider_connect_proxy", "PCP"},
    {"provider_connect_stub", "PCS"},
    {"running_form_info", "RFI"},
    {"form_bms_helper", "FBH"},
    {"form_bundle_event_callback", "FBEC"},
    {"form_ability_connection_reporter", "FACR"},
    {"form_ability_connection", "FAC"},
    {"form_event_handler", "FEH"},
    {"form_event_notify_connection", "FENC"},
    {"form_event_util", "FEU"},
    {"form_refresh_limiter", "FRL"},
    {"form_timer_mgr", "FTM"},
    {"form_dump_mgr", "FDM"},
    {"form_report", "FR"},
    {"form_serial_queue", "FSQ"},
    {"form_trust_mgr", "FTM"},
    {"form_util", "FU"},
    {"mem_status_listener", "MSL"},
    {"form_db_cache", "FDC"},
    {"form_db_info", "FDI"},
    {"form_rdb_data_mgr", "FRDM"},
    {"form_info_mgr", "FIM"},
    {"form_info_rdb_storage_mgr", "FIRSM"},
    {"form_info_storage", "FIS"},
    {"form_item_info", "FII"},
    {"form_record_report", "FRR"},
    {"form_basic_info_mgr", "FBIM"},
    {"form_cache_mgr", "FCM"},
    {"form_data_mgr", "FDM"},
    {"form_data_proxy_mgr", "FDPM"},
    {"form_data_proxy_record", "FDPR"},
    {"form_host_callback", "FHC"},
    {"form_host_queue", "FHQ"},
    {"form_host_record", "FHR"},
    {"form_host_task_mgr", "FHTM"},
    {"form_mgr_adapter", "FMA"},
    {"form_mgr_queue", "FMQ"},
    {"form_mgr_service", "FMS"},
    {"form_observer_record", "FOR"},
    {"form_observer_task_mgr", "FOTM"},
    {"form_resource_observer", "FRO"},
    {"form_acquire_connection", "FAC"},
    {"form_acquire_data_connection", "FADC"},
    {"form_acquire_state_connection", "FASC"},
    {"form_background_connection", "FBC"},
    {"form_batch_delete_connection", "FBDC"},
    {"form_cast_temp_connection", "FCTC"},
    {"form_configuration_update_connection", "FCUC"},
    {"form_delete_connection", "FDC"},
    {"form_location_connection", "FLC"},
    {"form_msg_event_connection", "FMEC"},
    {"form_refresh_connection", "FRC"},
    {"form_update_size_connection", "FUSC"},
    {"form_provider_mgr", "FPM"},
    {"form_provider_queue", "FPQ"},
    {"form_provider_task_mgr", "FPTM"},
    {"form_supply_callback", "FSC"},
    {"active_user_checker", "AUC"},
    {"add_finish_checker", "AFC"},
    {"calling_bundle_checker", "CBC"},
    {"calling_user_checker", "CUC"},
    {"self_form_checker", "SFC"},
    {"system_app_checker", "SAC"},
    {"untrust_app_checker", "UAC"},
    {"form_app_upgrade_refresh_impl", "FAURI"},
    {"form_data_refresh_impl", "FDRI"},
    {"form_force_refresh_impl", "FFRI"},
    {"form_host_refresh_impl", "FHRI"},
    {"form_net_conn_refresh_impl", "FNCRI"},
    {"form_next_time_refresh_impl", "FNTRI"},
    {"form_refresh_after_uncontrol_impl", "FRAUI"},
    {"form_timer_refresh_impl", "FTRI"},
    {"refresh_cache_mgr", "RCM"},
    {"refresh_check_mgr", "RCM"},
    {"refresh_control_mgr", "RCM"},
    {"refresh_exec_mgr", "REM"},
    {"form_refresh_mgr", "FRM"},
    {"form_render_connection", "FRC"},
    {"form_render_mgr_inner", "FRMI"},
    {"form_render_mgr", "FRM"},
    {"form_render_queue", "FRQ"},
    {"form_render_task_mgr", "FRTM"},
    {"form_sandbox_render_mgr_inner", "FSRMI"},
    {"form_event_queue", "FEQ"},
    {"form_event_retry_mgr", "FERM"},
    {"form_event_timeout_queue", "FETQ"},
    {"form_status_mgr", "FSM"},
    {"form_status_queue", "FSQ"},
    {"form_status_table", "FST"},
    {"form_status_task_mgr", "FSTM"},
    {"form_status", "FS"},
    {"form_distributed_mgr", "FDM"},
    {"form_bundle_forbid_mgr", "FBFM"},
    {"form_bundle_lock_mgr", "FBLM"},
    {"form_exempt_lock_mgr", "FELM"},
    {"form_ecological_rule_service", "FERS"},
    {"form_distributed_client", "FDC"},
    {"form_free_install_operator", "FFIO"},
    {"form_share_connection", "FSC"},
    {"form_share_mgr", "FSM"},
    {"form_share_task_mgr", "FSTM"},
    {"free_install_status_callback_proxy", "FISCP"},
    {"free_install_status_callback_stub", "FISCS"},
    {"form_render_report", "FRR"},
    {"param_common_event", "PCE"},
    {"param_manager", "PM"},
    {"param_reader", "PM"},
    {"form_router_proxy_mgr", "FRPM"},
    {"form_render_status_mgr", "FRSM"},
    {"form_render_status_table", "FRST"},
    {"form_render_status_task_mgr", "FRSTM"},
    {"form_render_status", "FRS"},
    {"form_memmgr_client", "FMC"},
    {"form_memory_guard", "FMG"},
    {"form_module_checker", "FMC"},
    {"form_render_event_report", "FRER"},
    {"form_render_impl", "FRI"},
    {"form_render_record", "FRR"},
    {"form_render_serial_queue", "FRSQ"},
    {"form_render_service_extension", "FRSE"},
    {"form_render_service_mgr", "FRSM"},
};

[[maybe_unused]] static std::string ConvertFmsFileName(const std::string& fileName)
{
    std::string fileBaseName = fileName;
    auto pos = fileName.find_last_of(".");
    if (pos == std::string::npos) {
        return fileBaseName;
    }
    fileBaseName = fileName.substr(0, pos); 
    const auto iter = fileNameMap_.find(fileBaseName);
    if (iter != fileNameMap_.end()) {
        return iter->second;
    }
    return fileBaseName;
}
}

#ifdef HILOG_FATAL
#undef HILOG_FATAL
#endif

#ifdef HILOG_ERROR
#undef HILOG_ERROR
#endif

#ifdef HILOG_WARN
#undef HILOG_WARN
#endif

#ifdef HILOG_INFO
#undef HILOG_INFO
#endif

#ifdef HILOG_BRIEF
#undef HILOG_BRIEF
#endif

#ifdef HILOG_DEBUG
#undef HILOG_DEBUG
#endif

#ifndef FMS_LOG_DOMAIN
#define FMS_LOG_DOMAIN 0xD001301
#endif

#ifndef FMS_LOG_TAG
#define FMS_LOG_TAG "FormManagerService"
#endif

#ifndef FMS_FUNC_FMT
#define FMS_FUNC_FMT "[%{public}s(%{public}s:%{public}d)]"
#endif

#ifndef FMS_FUNC_FMT_BRIEF
#define FMS_FUNC_FMT_BRIEF "[%{public}s:%{public}d]"
#endif

#ifndef FMS_FILE_NAME
#define FMS_FILE_NAME (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#ifndef FMS_FUNC_INFO
#define FMS_FUNC_INFO FMS_FILE_NAME, __FUNCTION__, __LINE__
#endif

#ifndef FMS_FUNC_INFO_BRIEF
#define FMS_FUNC_INFO_BRIEF FMS_FILE_NAME, __LINE__
#endif

#define HILOG_BRIEF(fmt, ...) do { \
    (void)HILOG_IMPL(LOG_CORE, LOG_INFO, FMS_LOG_DOMAIN, FMS_LOG_TAG, \
    FMS_FUNC_FMT_BRIEF fmt, FMS_FUNC_INFO_BRIEF, ##__VA_ARGS__);      \
} while (0)

#define FMS_PRINT_LOG(level, fmt, ...)                                                            \
    do {                                                                                          \
        std::string fileName = OHOS::AAFwk::ConvertFmsFileName(std::string(FMS_FILE_NAME));       \
        ((void)HILOG_IMPL(LOG_CORE, level, FMS_LOG_DOMAIN,                                        \
        FMS_LOG_TAG, FMS_FUNC_FMT fmt, fileName.c_str(), __FUNCTION__, __LINE__, ##__VA_ARGS__)); \
    } while (0)

#define HILOG_DEBUG(fmt, ...) FMS_PRINT_LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define HILOG_INFO(fmt, ...) FMS_PRINT_LOG(LOG_INFO, fmt, ##__VA_ARGS__)
#define HILOG_WARN(fmt, ...) FMS_PRINT_LOG(LOG_WARN, fmt, ##__VA_ARGS__)
#define HILOG_ERROR(fmt, ...) FMS_PRINT_LOG(LOG_ERROR, fmt, ##__VA_ARGS__)
#define HILOG_FATAL(fmt, ...) FMS_PRINT_LOG(LOG_FATAL, fmt, ##__VA_ARGS__)

#else

#define HILOG_FATAL(...)
#define HILOG_ERROR(...)
#define HILOG_WARN(...)
#define HILOG_INFO(...)
#define HILOG_DEBUG(...)
#endif  // CONFIG_HILOG
#endif  // OHOS_FORM_FWK_FMS_LOG_WRAPPER_H
