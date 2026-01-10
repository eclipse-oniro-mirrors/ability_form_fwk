/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_RES_SCHED_H
#define OHOS_FORM_FWK_FORM_RES_SCHED_H

#include <stdint.h>
#include <unistd.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormResSched
 * Form resource schedule adapter.
 */
class FormResSched {
public:
    FormResSched(int32_t userId);
    ~FormResSched();

    /**
     * @brief Report form layout start to rss.
     */
    void ReportFormLayoutStart();

    /**
     * @brief Report form layout end to rss.
     */
    void ReportFormLayoutEnd();

private:
    /**
     * @brief Report premote frs's priority to rss.
     * @param pid The connection's key of form ability connection.
     * @param isStart True for form layout start, false for form layout end.
     */
    void ReportToRss(pid_t pid, int32_t uid, bool isStart);

private:
    int32_t userId_;
    pid_t pid_ = 0;
    int32_t uid_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_RES_SCHED_H
