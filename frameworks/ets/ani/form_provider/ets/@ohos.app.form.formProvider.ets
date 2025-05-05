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

import { BusinessError } from '@ohos.base';

export namespace formProvider {

  loadLibrary("formProvider_ani.z");

  native function setFormNextRefreshTime_inner(formId: string, minute: number): void;

  export function setFormNextRefreshTime(formId: string, minute: number): Promise<BusinessError> {
    return new Promise<BusinessError>((resolve, reject): void => {
      taskpool.execute((): void => { return setFormNextRefreshTime_inner(formId, minute); })
        .then((ret: NullishType): void => {
          let r = ret as BusinessError;
          resolve(r);
        })
        .catch((ret: NullishType): void => {
          reject(ret as BusinessError);
        });
    });
  }

  export function setFormNextRefreshTime(formId: string, minute: number,
    callback: (err: BusinessError) => void): void {
    taskpool.execute((): void => { return setFormNextRefreshTime_inner(formId, minute); })
      .then((ret: NullishType): void => {
        callback(new BusinessError());
      })
      .catch((ret: NullishType): void => {
        callback(ret as BusinessError);
      });
  }
}
