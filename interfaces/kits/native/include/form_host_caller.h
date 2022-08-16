/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_CALLER_H
#define OHOS_FORM_FWK_FORM_HOST_CALLER_H

#include <iremote_object.h>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostCaller
 * The caller of the form host.
 */
class FormHostCaller {
public:
    explicit FormHostCaller(const sptr<IRemoteObject> &callerToken) : callerToken_(callerToken) {}
    ~FormHostCaller() = default;
private:
    sptr<IRemoteObject> callerToken_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HOST_CALLER_H
