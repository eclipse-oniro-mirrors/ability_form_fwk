/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "form_util.h"

#include <chrono>
#include <cinttypes>
#include <regex>

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "ipc_skeleton.h"
#include "os_account_manager_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t SEC_TO_NANOSEC = 1000000000;
constexpr int64_t SEC_TO_MILLISEC = 1000;
constexpr int64_t MILLISEC_TO_NANOSEC = 1000000;
constexpr int64_t INVALID_UDID_HASH = 0;
constexpr int32_t SYSTEM_UID = 1000;
constexpr int INT_64_LENGTH = 19;
constexpr int ZERO_VALUE = 0;
constexpr int BASE_NUMBER = 9;
constexpr int DECIMAL_VALUE = 10;
} // namespace

using namespace std;
using namespace std::chrono;

/**
 * @brief create want for form.
 * @param formName The name of the form.
 * @param specificationId specification id.
 * @param isTemporaryForm temporary form or not.
 * @param want The want of the form.
 */
void FormUtil::CreateFormWant(const std::string &formName,
    const int32_t specificationId,  const bool isTemporaryForm, Want &want)
{
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, specificationId);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, isTemporaryForm);
}

/**
 * @brief create default want for form.
 * @param want The want of the form..
 * @param uri The uri.
 * @param connectId connect id.
 */
void FormUtil::CreateDefaultFormWant(Want &want, const std::string &uri, const int32_t connectId)
{
    want.SetParam(Constants::FORM_CONNECT_ID, connectId);
    want.SetParam(Constants::FORM_SUPPLY_INFO, uri);
}

/**
 * @brief create form id for form.
 * @param udidHash udid hash
 * @return new form id.
 */
int64_t FormUtil::GenerateFormId(int64_t udidHash)
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_REALTIME, &t);

    int64_t elapsedTime { ((t.tv_sec) * SEC_TO_NANOSEC + t.tv_nsec) };
    size_t elapsedHash = std::hash<std::string>()(std::to_string(elapsedTime));
    HILOG_INFO("GenerateFormId generate elapsed hash %{public}zu", elapsedHash);
    uint64_t unsignedUdidHash = static_cast<uint64_t>(udidHash);
    uint64_t formId = unsignedUdidHash | (uint32_t)(elapsedHash & 0x000000007fffffffL);
    int64_t ret = static_cast<int64_t>(formId);
    HILOG_INFO("GenerateFormId generate formId %{public}" PRId64 "", ret);
    return ret;
}

/**
 * @brief padding form id.
 * @param formId The id of the form.
 * @param udidHash udid hash
 * @return new form id.
 */
int64_t FormUtil::PaddingUdidHash(uint64_t formId, uint64_t udidHash)
{
    // Compatible with int form id.
    if ((formId & 0xffffffff00000000L) == 0) {
        return udidHash | formId;
    }

    return formId;
}
/**
 * @brief create udid hash.
 * @param udidHash udid hash.
 * @return Returns true on success, false on failure.
 */
bool FormUtil::GenerateUdidHash(int64_t &udidHash)
{
    HILOG_INFO("%{public}s start, udidHash:%{private}s", __func__, std::to_string(udidHash).c_str());
    if (udidHash != INVALID_UDID_HASH) {
        return true;
    }

    u_int64_t hashId = 0L;
    const int32_t thirtyTwo = 32;
    udidHash = (hashId & 0x0000000000ffffffL) << thirtyTwo;
    if (udidHash < 0) {
        udidHash = 0L;
    }
    HILOG_INFO("%{public}s, generate hash %{private}s", __func__, std::to_string(udidHash).c_str());
    return true;
}
/**
 * @brief Get current system nanosecond.
 * @return Current system nanosecond.
 */
int64_t FormUtil::GetCurrentNanosecond()
{
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * SEC_TO_NANOSEC + ts.tv_nsec);
}
/**
 * @brief Get current system millisecond.
 * @return Current system millisecond.
 */
int64_t FormUtil::GetCurrentMillisecond()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (ts.tv_sec * SEC_TO_MILLISEC + ts.tv_nsec / MILLISEC_TO_NANOSEC);
}

int64_t FormUtil::GetCurrentMicrosecond()
{
    system_clock::time_point pointTime = system_clock::now();
    auto timeMicroseconds = chrono::duration_cast<chrono::microseconds>(pointTime.time_since_epoch());
    return timeMicroseconds.count();
}

int64_t FormUtil::GetNowMillisecond()
{
    system_clock::time_point pointTime = system_clock::now();
    auto timeMilliseconds = chrono::duration_cast<chrono::milliseconds>(pointTime.time_since_epoch());
    return timeMilliseconds.count();
}

/**
 * @brief Get millisecond from tm.
 * @param tmAtTime tm time.
 * @return Millisecond.
 */
int64_t FormUtil::GetMillisecondFromTm(struct tm &tmAtTime)
{
    time_t inputTime = mktime(&tmAtTime);
    if (inputTime == -1) {
        HILOG_ERROR("%{public}s fail, mktime failed.", __func__);
        return -1;
    }
    system_clock::time_point pointTime = system_clock::from_time_t(inputTime);
    auto timeMilliseconds = chrono::duration_cast<chrono::milliseconds>(pointTime.time_since_epoch());
    return timeMilliseconds.count();
}

/**
* @brief split string.
 * @param in string.
 * @param delim delimiter.
 * @return string list.
 */
std::vector<std::string> FormUtil::StringSplit(const std::string &in, const std::string &delim)
{
    std::regex reg { delim };
    return std::vector<std::string> {
        std::sregex_token_iterator(in.begin(), in.end(), reg, -1),
        std::sregex_token_iterator()
    };
}

/**
 * @brief get current active account id.
 * @return int current active account id.
 */
int FormUtil::GetCurrentAccountId()
{
    std::vector<int32_t> activeList;
    ErrCode errCode = DelayedSingleton<OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    if (errCode != ERR_OK) {
        HILOG_ERROR("QueryActiveOsAccountIds failed.");
        return Constants::ANY_USERID;
    }
    if (activeList.empty()) {
        HILOG_ERROR("QueryActiveOsAccountIds is empty, no accounts.");
        return Constants::ANY_USERID;
    }

    return activeList.front();
}

bool FormUtil::IsSACall()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    HILOG_DEBUG("callerToken : %{private}u", callerToken);

    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE) {
        HILOG_DEBUG("caller tokenType is native, verify success");
        return true;
    }

    if (IPCSkeleton::GetCallingUid() == SYSTEM_UID) {
        HILOG_DEBUG("callingUid is native, verify success");
        return true;
    }

    HILOG_DEBUG("Not SA called.");
    return false;
}

bool FormUtil::VerifyCallingPermission(const std::string &permissionName)
{
    HILOG_DEBUG("called. permission name is:%{public}s", permissionName.c_str());
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(callerToken, permissionName);
    if (ret == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
        HILOG_ERROR("permission %{public}s: PERMISSION_DENIED", permissionName.c_str());
        return false;
    }
    HILOG_DEBUG("Verify calling permission success");
    return true;
}

bool FormUtil::ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
{
    size_t strLength = strInfo.size();
    if (strLength == ZERO_VALUE) {
        int64Value = ZERO_VALUE;
        return true;
    }
    std::regex pattern("^0|-?[1-9][0-9]{0,18}$"); // "^-?[0-9]{1,19}$"
    std::smatch match;
    if (regex_match(strInfo, match, pattern)) {
        HILOG_DEBUG("%{public}s, regex_match successed.", __func__);
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") { // maximum: 9223372036854775807
            if (strLength < INT_64_LENGTH) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int maxSubValue = std::stoi(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            // Means 0x7FFFFFFFFFFFFFFF remove the first number:(2^63 - 1 - 9 * 10 ^ 19)
            int subValue = std::stoll(strInfo.substr(ZERO_VALUE + 1, INT_64_LENGTH - 1));
            if (strLength == INT_64_LENGTH && subValue <= INT64_MAX - BASE_NUMBER *
                (int64_t)pow(DECIMAL_VALUE, INT_64_LENGTH - 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
        if (strLength < INT_64_LENGTH + 1) { // The minimum value: -9223372036854775808
            int64Value = std::stoll(strInfo);
            return true;
        }
        if (strLength == INT_64_LENGTH + 1) {
            int minSubValue = std::stoi(strInfo.substr(1, 1));
            if (minSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }

            // Means 0x8000000000000000 remove the first number:-(2^63 - 9 * 10 ^ 19)
            if (std::stoll(strInfo.substr(ZERO_VALUE + 2, INT_64_LENGTH - 1)) <=
                (INT64_MAX - BASE_NUMBER * (int64_t)pow(DECIMAL_VALUE, INT_64_LENGTH) + 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
    }
    HILOG_DEBUG("%{public}s, regex_match failed.", __func__);
    return false;
}
} // namespace AppExecFwk
} // namespace OHOS