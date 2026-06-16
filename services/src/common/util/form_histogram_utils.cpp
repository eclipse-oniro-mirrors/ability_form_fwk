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

#include "common/util/form_histogram_utils.h"

#ifdef FORM_FWK_SUPPORT_API_METRICS
#include "histogram_plugin_macros.h"
#endif

namespace OHOS {
namespace AppExecFwk {
void FormHistogramUtils::ReportHistogramBoolean(const std::string& name, bool sample)
{
#ifdef FORM_FWK_SUPPORT_API_METRICS
    HISTOGRAM_BOOLEAN(name.c_str(), static_cast<int32_t>(sample));
#endif
}

void FormHistogramUtils::ReportHistogramEnumeration(const std::string& name, int32_t sample, int32_t boundary)
{
#ifdef FORM_FWK_SUPPORT_API_METRICS
    HISTOGRAM_ENUMERATION(name.c_str(), sample, boundary);
#endif
}

void FormHistogramUtils::ReportHistogramCount(const std::string& name, int32_t sample,
    int32_t min, int32_t max, int32_t bucketCount)
{
#ifdef FORM_FWK_SUPPORT_API_METRICS
    HISTOGRAM_CUSTOM_COUNTS(name.c_str(), sample, min, max, bucketCount);
#endif
}

void FormHistogramUtils::ReportHistogramTimes(const std::string& name, int32_t sampleMs)
{
#ifdef FORM_FWK_SUPPORT_API_METRICS
    HISTOGRAM_TIMES(name.c_str(), sampleMs);
#endif
}

void FormHistogramUtils::ReportHistogramPercentage(const std::string& name, int32_t sample)
{
#ifdef FORM_FWK_SUPPORT_API_METRICS
    HISTOGRAM_PERCENTAGE(name.c_str(), sample);
#endif
}

}  // namespace AppExecFwk
}  // namespace OHOS
