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

#ifndef OHOS_FORM_FWK_FORM_WANT_H
#define OHOS_FORM_FWK_FORM_WANT_H

#include <shared_mutex>
#include <unordered_set>
#include <string>

#include "parcel.h"
#include "want.h"
#include "want_params.h"
#include "form_constants.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {

using Want = OHOS::AAFwk::Want;

/**
 * @class FormWant
 * @brief Want parameter wrapper for form framework internal parameter passing
 *
 * Design highlights:
 * - Want member property (contains bundleName/abilityName/moduleName + all parameters)
 * - Internal parameter filter list for domain boundary protection
 * - Read-write lock for thread-safe data protection
 *
 * Usage scenarios:
 * - Internal use in form domain (form_fwk, arkui_ace_engine, ability_runtime) uses FormWant
 * - Call FilterInternalParams() to filter internal params when passing outside form domain
 */
class FormWant {
public:
    /**
     * @brief Default constructor
     */
    FormWant();

    /**
     * @brief Copy constructor
     * @param other FormWant object
     */
    FormWant(const FormWant &other);

    /**
     * @brief Constructor with Want parameter
     * @param want Want object
     */
    explicit FormWant(const Want &want);

    /**
     * @brief Destructor
     */
    ~FormWant() = default;

    /**
     * @brief Copy assignment operator
     * @param other FormWant object
     * @return FormWant reference
     */
    FormWant &operator=(const FormWant &other);

    /**
     * @brief Get Want object (auto read lock)
     * @return Copy of Want object
     */
    Want GetWant() const;

    /**
     * @brief Set int type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, int value);

    /**
     * @brief Set int64_t type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, int64_t value);

    /**
     * @brief Set string type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, const std::string &value);

    /**
     * @brief Set bool type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, bool value);

    /**
     * @brief Set double type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, double value);

    /**
     * @brief Set float type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, float value);

    /**
     * @brief Set IRemoteObject type parameter (auto write lock)
     * @param key Parameter name
     * @param value Parameter value
     * @return FormWant reference (supports chain calls)
     */
    FormWant &SetParam(const std::string &key, const sptr<IRemoteObject> &value);

    /**
     * @brief Get int type parameter (auto read lock)
     * @param key Parameter name
     * @param defaultValue Default value
     * @return Parameter value
     */
    int GetIntParam(const std::string &key, int defaultValue) const;

    /**
     * @brief Get int64_t type parameter (auto read lock)
     * @param key Parameter name
     * @param defaultValue Default value
     * @return Parameter value
     */
    int64_t GetLongParam(const std::string &key, int64_t defaultValue) const;

    /**
     * @brief Get string type parameter (auto read lock)
     * @param key Parameter name
     * @return Parameter value
     */
    std::string GetStringParam(const std::string &key) const;

    /**
     * @brief Get bool type parameter (auto read lock)
     * @param key Parameter name
     * @param defaultValue Default value
     * @return Parameter value
     */
    bool GetBoolParam(const std::string &key, bool defaultValue) const;

    /**
     * @brief Get double type parameter (auto read lock)
     * @param key Parameter name
     * @param defaultValue Default value
     * @return Parameter value
     */
    double GetDoubleParam(const std::string &key, double defaultValue) const;

    /**
     * @brief Get float type parameter (auto read lock)
     * @param key Parameter name
     * @param defaultValue Default value
     * @return Parameter value
     */
    float GetFloatParam(const std::string &key, float defaultValue) const;

    /**
     * @brief Get IRemoteObject type parameter (auto read lock)
     * @param key Parameter name
     * @return Parameter value
     */
    sptr<IRemoteObject> GetRemoteObject(const std::string &key) const;

    /**
     * @brief Check if parameter exists (auto read lock)
     * @param key Parameter name
     * @return true-exists, false-not exists
     */
    bool HasParameter(const std::string &key) const;

    /**
     * @brief Remove parameter (auto write lock)
     * @param key Parameter name
     */
    void RemoveParam(const std::string &key);

    /**
     * @brief Get filtered Want (for passing outside form domain)
     * @return Filtered Want object
     */
    Want GetFilteredWant() const;

    /**
     * @brief Filter internal parameters (static method for unified management)
     * @param want Want object
     * @return Filtered Want
     */
    static Want FilterInternalParams(const Want &want);

    /**
     * @brief Merge Want parameters to current object (auto write lock)
     * @param want Want object
     * @return FormWant reference (supports chain calls)
     */
    FormWant &MergeFrom(const Want &want);

    /**
     * @brief Merge Want parameters to target Want object (static method)
     * @param target Target Want object
     * @param source Source Want object
     */
    static void MergeWantParams(Want &target, const Want &source);

    /**
     * @brief Extract FORM_HOST_PARAM_NAMES parameters to target Want (member method)
     * @param target Target Want object (will be modified)
     */
    void ExtractHostParamsToWant(Want &target) const;

private:
    Want want_;
    mutable std::shared_mutex mutex_;

    static const std::unordered_set<std::string> FILTER_INTERNAL_PARAMS_;
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_WANT_H
