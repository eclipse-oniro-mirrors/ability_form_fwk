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

#include "form_want.h"
#include <algorithm>

namespace OHOS {
namespace AppExecFwk {

using WantParams = OHOS::AAFwk::WantParams;

const std::unordered_set<std::string> FormWant::FILTER_INTERNAL_PARAMS_ = {
    Constants::FORM_CONNECT_ID,
    Constants::ACQUIRE_TYPE,
    Constants::FORM_SUPPLY_INFO,
    Constants::PARAM_FORM_HOST_TOKEN,
    Constants::FORM_COMP_ID,
    Constants::FORM_DENSITY,
    Constants::FORM_PROCESS_ON_ADD_SURFACE,
    Constants::FORM_ALLOW_UPDATE,
    Constants::PARAM_LAYOUT_WIDTH_KEY,
    Constants::PARAM_LAYOUT_HEIGHT_KEY,
    Constants::PARAM_FORM_VIEW_SCALE,
    Constants::IS_ADD_FORM_BY_HOST,
    Constants::PARAM_DELETE_BACKGROUND_IMAGE,
    Constants::PARAM_FORM_COLOR_MODE_KEY,
    Constants::CONNECT_TO_RENDER,  // form_fwk新增：渲染连接标识
};

FormWant::FormWant()
{
    want_ = Want();
}

FormWant::FormWant(const FormWant &other)
{
    std::lock(mutex_, other.mutex_);
    std::lock_guard<std::shared_mutex> lock1(mutex_, std::adopt_lock);
    std::lock_guard<std::shared_mutex> lock2(other.mutex_, std::adopt_lock);
    want_ = other.want_;
}

FormWant &FormWant::operator=(const FormWant &other)
{
    if (this == &other) {
        return *this;
    }

    std::lock(mutex_, other.mutex_);
    std::lock_guard<std::shared_mutex> lock1(mutex_, std::adopt_lock);
    std::lock_guard<std::shared_mutex> lock2(other.mutex_, std::adopt_lock);

    want_ = other.want_;
    return *this;
}

FormWant::FormWant(const Want &want)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_ = want;
}

Want FormWant::GetWant() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_;
}

FormWant &FormWant::SetParam(const std::string &key, int value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, long value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, const std::string &value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, bool value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, double value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, float value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

FormWant &FormWant::SetParam(const std::string &key, const sptr<IRemoteObject> &value)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.SetParam(key, value);
    return *this;
}

int FormWant::GetIntParam(const std::string &key, int defaultValue) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.GetIntParam(key, defaultValue);
}

long FormWant::GetLongParam(const std::string &key, long defaultValue) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.GetLongParam(key, defaultValue);
}

std::string FormWant::GetStringParam(const std::string &key) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.GetStringParam(key);
}

bool FormWant::GetBoolParam(const std::string &key, bool defaultValue) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.GetBoolParam(key, defaultValue);
}

sptr<IRemoteObject> FormWant::GetRemoteObject(const std::string &key) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.GetRemoteObject(key);
}

bool FormWant::HasParameter(const std::string &key) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return want_.HasParameter(key);
}

void FormWant::RemoveParam(const std::string &key)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    want_.RemoveParam(key);
}

Want FormWant::FilterInternalParams(const Want &want)
{
    Want filteredWant(want);
    for (const std::string &param : FILTER_INTERNAL_PARAMS_) {
        filteredWant.RemoveParam(param);
    }
    return filteredWant;
}

Want FormWant::GetFilteredWant() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return FilterInternalParams(want_);
}

FormWant &FormWant::MergeFrom(const Want &want)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    WantParams currentParams = want_.GetParams();
    WantParams newParams = want.GetParams();
    for (const auto &[key, value] : newParams.GetParams()) {
        currentParams.SetParam(key, value);
    }
    want_.SetParams(currentParams);
    return *this;
}

void FormWant::MergeWantParams(Want &target, const Want &source)
{
    WantParams targetParams = target.GetParams();
    WantParams sourceParams = source.GetParams();
    for (const auto &[key, value] : sourceParams.GetParams()) {
        targetParams.SetParam(key, value);
    }
    target.SetParams(targetParams);
}

void FormWant::ExtractHostParamsToWant(Want &target) const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    WantParams sourceParams = want_.GetParams();
    WantParams targetParams = target.GetParams();
    for (const auto &paramKey : Constants::FORM_HOST_PARAM_NAMES) {
        if (!sourceParams.HasParam(paramKey)) {
            continue;
        }
        auto paramValue = sourceParams.GetParam(paramKey);
        if (paramValue != nullptr) {
            targetParams.SetParam(paramKey, paramValue);
        }
    }
    target.SetParams(targetParams);
}

}  // namespace AppExecFwk
}  // namespace OHOS
