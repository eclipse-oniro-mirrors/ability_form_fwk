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

#ifndef FORM_HISTOGRAM_UTILS_H
#define FORM_HISTOGRAM_UTILS_H

#include <string>


namespace OHOS {
namespace AppExecFwk {

class FormHistogramUtils {
public:
    static void ReportHistogramBoolean(const std::string& name, bool sample);
    static void ReportHistogramEnumeration(const std::string& name, int32_t sample, int32_t boundary);
    static void ReportHistogramCount(const std::string& name, int32_t sample,
        int32_t min, int32_t max, int32_t bucketCount);
    static void ReportHistogramTimes(const std::string& name, int32_t sampleMs);
    static void ReportHistogramPercentage(const std::string& name, int32_t sample);
private:
    FormHistogramUtils() = default;
    ~FormHistogramUtils() = default;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FORM_HISTOGRAM_UTILS_H
