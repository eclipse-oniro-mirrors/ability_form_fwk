/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#ifndef OHOS_FORM_FWK_FORM_UTIL_H
#define OHOS_FORM_FWK_FORM_UTIL_H

#include "want.h"

namespace OHOS {
namespace AppExecFwk {
constexpr int BASE_REQUEST_CODE_NUM = 10;
using Want = OHOS::AAFwk::Want;
/**
 * @class FormUtil
 * form utils.
 */
class FormUtil {
public:
    /**
     * @brief create form id for form.
     * @param udidHash udid hash
     * @return new form id.
     */
    static int64_t GenerateFormId(int64_t udidHash);

    /**
     * @brief delete form id for form.
     * @param formId The id of the form.
     */
    static void DeleteFormId(int64_t formId);

    /**
     * @brief padding form id.
     * @param formId The id of the form.
     * @param udidHash udid hash.
     * @return new form id.
     */
    static int64_t PaddingUdidHash(uint64_t formId, uint64_t udidHash);

    /**
     * @brief create udid hash.
     * @param udidHash udid hash.
     * @return Returns true on success, false on failure.
     */
    static bool GenerateUdidHash(int64_t &udidHash);
    /**
     * @brief Get current system nanosecond.
     * @return Current system nanosecond.
     */
    static int64_t GetCurrentNanosecond();
    /**
     * @brief Get current system millisecond.
     * @return Current system millisecond.
     */
    static int64_t GetCurrentMillisecond();
    /**
     * @brief Get current system GetCurrentSteadyClockMillseconds.
     * @return Current system GetCurrentSteadyClockMillseconds.
     */
    static int64_t GetCurrentSteadyClockMillseconds();

    /**
     * @brief Get current system millisecond.
     * @return Current system millisecond.
     */
    static int64_t GetNowMillisecond();

    /**
     * @brief Get millisecond from tm.
     * @param tmAtTime tm time.
     * @return Millisecond.
     */
    static int64_t GetMillisecondFromTm(struct tm &tmAtTime);

    /**
     * @brief split string.
     * @param in string.
     * @param delim delimiter.
     * @return string list.
     */
    static std::vector<std::string> StringSplit(const std::string &in, const std::string &delim);
    /**
     * @brief get current active account id.
     * @return int current active account id.
     */
    static int GetCurrentAccountId();

    /**
     * @brief Check if the caller ability is SA.
     * @return Returns true if is SA call; returns false otherwise.
     */
    static bool IsSACall();

    /**
     * @brief Checks whether the caller has a certain permission.
     * @param permissionName The name of the permission.
     * @return Returns true if the caller has certain permissions; returns false otherwise.
     */
    static bool VerifyCallingPermission(const std::string &permissionName);

    /**
     * @brief Convert string to int64_t
     *
     * @param[in] strInfo The string information
     * @param[out] int64Value Convert string to int64_t
     *
     * @return Return the convert result
     */
    static bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value);

    static int ConvertStringToInt(const std::string &strInfo, int radix = BASE_REQUEST_CODE_NUM);

    static long long ConvertStringToLongLong(const std::string &strInfo, int radix = BASE_REQUEST_CODE_NUM);

    static bool IsActiveUser(const int32_t userId);

    static void GetActiveUsers(std::vector<int32_t> &activeList);

    /**
     * @brief Get caller user ID.
     * @param callingUid calling Uid.
     * @return Returns user ID.
     */
    static int32_t GetCallerUserId(const int callingUid);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_UTIL_H
