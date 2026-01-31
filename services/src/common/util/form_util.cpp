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

#include "common/util/form_util.h"

#include <set>
#include <thread>
#include <chrono>
#include <cinttypes>
#include <regex>

#include "accesstoken_kit.h"
#include "bundle_constants.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "ipc_skeleton.h"
#include "os_account_manager_wrapper.h"
#include "os_account_manager.h"

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
constexpr int64_t HEAD_BIT_NUM = 9000000000000000000;
} // namespace

using namespace std;
using namespace std::chrono;

static std::set<uint64_t> s_memFormIds;
static std::mutex s_memFormIdsMutex;

/**
 * @brief create form id for form.
 * @param udidHash udid hash
 * @return new form id.
 */
int64_t FormUtil::GenerateFormId(int64_t udidHash)
{
    set<uint64_t>::iterator it;
    const int retryTimes = 5;
    const int delayMs = 1;
    int64_t elapsedTime = 0;
    size_t elapsedHash = 0;
    uint64_t unsignedUdidHash = 0;
    uint64_t formId = 0;
    int64_t ret = -1;
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    for (int i = 0; i < retryTimes; i++) {
        clock_gettime(CLOCK_REALTIME, &t);
        elapsedTime = (t.tv_sec) * SEC_TO_NANOSEC + t.tv_nsec;
        elapsedHash = std::hash<std::string>()(std::to_string(elapsedTime));
        unsignedUdidHash = static_cast<uint64_t>(udidHash);
        formId = unsignedUdidHash | (uint32_t)(elapsedHash & 0x000000007fffffffL);
        ret = static_cast<int64_t>(formId);
        std::lock_guard<std::mutex> lock(s_memFormIdsMutex);
        it = s_memFormIds.find(formId);
        if (it != s_memFormIds.end()) {
            HILOG_INFO("repeated formId:%{public}" PRId64, ret);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        } else {
            s_memFormIds.insert(formId);
            break;
        }
    }
    HILOG_INFO("generate elapsed hash %{public}zu, formId:%{public}" PRId64, elapsedHash, ret);
    return ret;
}

/**
@brief delete form id for form.
@param formId The id of the form.
*/
void FormUtil::DeleteFormId(int64_t formId)
{
    std::lock_guard<std::mutex> lock(s_memFormIdsMutex);
    s_memFormIds.erase(static_cast<uint64_t>(formId));
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
    HILOG_INFO("udidHash:%{private}s", std::to_string(udidHash).c_str());
    if (udidHash != INVALID_UDID_HASH) {
        return true;
    }

    u_int64_t hashId = 0L;
    const int32_t thirtyTwo = 32;
    udidHash = (hashId & 0x0000000000ffffffL) << thirtyTwo;
    if (udidHash < 0) {
        udidHash = 0L;
    }
    HILOG_INFO("generate hash %{private}s", std::to_string(udidHash).c_str());
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

int64_t FormUtil::GetCurrentSteadyClockMillseconds()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
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
        HILOG_ERROR("mktime failed");
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
        HILOG_ERROR("QueryActiveOsAccountIds failed");
        return Constants::ANY_USERID;
    }
    if (activeList.empty()) {
        HILOG_ERROR("empty QueryActiveOsAccountIds,no accounts");
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
        HILOG_DEBUG("callingUid is native,verify success");
        return true;
    }

    HILOG_DEBUG("call");
    return false;
}

bool FormUtil::VerifyCallingPermission(const std::string &permissionName)
{
    HILOG_DEBUG("call.permission name is:%{public}s", permissionName.c_str());
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
        HILOG_DEBUG("regex_match successed");
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") { // maximum: 9223372036854775807
            if (strLength < INT_64_LENGTH) {
                int64Value = static_cast<int64_t>(ConvertStringToLongLong(strInfo));
                return true;
            }
            int maxSubValue = ConvertStringToInt(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER) {
                int64Value = static_cast<int64_t>(ConvertStringToLongLong(strInfo));
                return true;
            }
            // Means 0x7FFFFFFFFFFFFFFF remove the first number:(2^63 - 1 - 9 * 10 ^ 19)
            int64_t subValue = static_cast<int64_t>(ConvertStringToLongLong(strInfo.substr(ZERO_VALUE + 1,
                INT_64_LENGTH - 1)));
            if (strLength == INT_64_LENGTH && subValue <= (INT64_MAX - HEAD_BIT_NUM)) {
                int64Value = static_cast<int64_t>(ConvertStringToLongLong(strInfo));
                return true;
            }
            return false;
        }
        if (strLength < INT_64_LENGTH + 1) { // The minimum value: -9223372036854775808
            int64Value = static_cast<int64_t>(ConvertStringToLongLong(strInfo));
            return true;
        }
        if (strLength == INT_64_LENGTH + 1) {
            int minSubValue = ConvertStringToInt(strInfo.substr(1, 1));
            if (minSubValue < BASE_NUMBER) {
                int64Value = static_cast<int64_t>(ConvertStringToLongLong(strInfo));
                return true;
            }

            // Means 0x8000000000000000 remove the first number:-(2^63 - 9 * 10 ^ 19)
            int64_t subValue = static_cast<int64_t>(ConvertStringToLongLong(strInfo.substr(ZERO_VALUE + 2,
                INT_64_LENGTH - 1)));
            if (subValue <= (INT64_MAX - HEAD_BIT_NUM + 1)) {
                int64Value = ConvertStringToLongLong(strInfo);
                return true;
            }
        }
    }
    HILOG_DEBUG("regex_match failed");
    return false;
}

int FormUtil::ConvertStringToInt(const std::string &strInfo, int radix)
{
    return static_cast<int>(strtol(strInfo.c_str(), nullptr, radix));
}

long long FormUtil::ConvertStringToLongLong(const std::string &strInfo, int radix)
{
    return static_cast<long long>(strtoll(strInfo.c_str(), nullptr, radix));
}

bool FormUtil::IsActiveUser(const int32_t userId)
{
    std::vector<int32_t> activeList;
    auto errCode = DelayedSingleton<OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    auto iter = std::find(activeList.begin(), activeList.end(), userId);
    return iter != activeList.end() && errCode == ERR_OK;
}

void FormUtil::GetActiveUsers(std::vector<int32_t> &activeList)
{
    ErrCode errCode = DelayedSingleton<OsAccountManagerWrapper>::GetInstance()->QueryActiveOsAccountIds(activeList);
    if (errCode != ERR_OK) {
        HILOG_ERROR("QueryActiveOsAccountIds failed");
        return;
    }
}

int32_t FormUtil::GetCallerUserId(const int callingUid)
{
    // get caller userId
    int32_t userId = callingUid / Constants::CALLING_UID_TRANSFORM_DIVISOR;
    (void)DelayedSingleton<OsAccountManagerWrapper>::GetInstance()->GetOsAccountLocalIdFromUid(callingUid, userId);
    return userId;
}

void FormUtil::GetForegroundUsers(std::vector<int32_t> &foregroundList)
{
    std::vector<AccountSA::ForegroundOsAccount> accounts;
    ErrCode errCode = AccountSA::OsAccountManager::GetForegroundOsAccounts(accounts);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Query foreground accounts failed");
        return;
    }
    for (AccountSA::ForegroundOsAccount &account : accounts) {
        foregroundList.push_back(account.localId);
    }
}
} // namespace AppExecFwk
} // namespace OHOS