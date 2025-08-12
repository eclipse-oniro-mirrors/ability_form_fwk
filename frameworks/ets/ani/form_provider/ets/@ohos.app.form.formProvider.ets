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

import { AsyncCallback } from '@ohos.base';

export namespace formProvider {

  loadLibrary("formProvider_ani.z");

  native function setFormNextRefreshTime_inner(formId: string, minute: int): void;

  export function setFormNextRefreshTimeReturnsPromise(formId: string, minute: int): Promise<void> {
    return new Promise<void>(() => {
      setFormNextRefreshTime_inner(formId, minute);
    });
  }

  export function setFormNextRefreshTimeWithCallback(formId: string, minute: int,
    callback: AsyncCallback<void>): void {
    setFormNextRefreshTime_inner(formId, minute);
  }

  overload setFormNextRefreshTime { setFormNextRefreshTimeReturnsPromise, setFormNextRefreshTimeWithCallback }
}
