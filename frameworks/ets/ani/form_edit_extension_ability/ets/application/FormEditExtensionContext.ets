/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import { BusinessError, AsyncCallback } from '@ohos.base';
import UIExtensionContext from 'application.UIExtensionContext';
import type Want from '@ohos.app.ability.Want';
import type { AbilityResult } from 'ability.abilityResult';

class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export default class FormEditExtensionContext extends UIExtensionContext {

  native nativeStartSecondPage(want: Want, callback: AsyncCallbackWrapper<AbilityResult>): void;

  native nativeStartUIAbility(want: Want, callback: AsyncCallbackWrapper<AbilityResult>): void;

  startSecondPage(want: Want): Promise<AbilityResult> {
    let p: Promise<AbilityResult> =
      new Promise<AbilityResult>((resolve: (data: AbilityResult) => void, reject: (err: BusinessError) => void): void => {
        let myCall: AsyncCallbackWrapper<AbilityResult> = new AsyncCallbackWrapper<AbilityResult>(
          (err: BusinessError | null, data: AbilityResult | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as AbilityResult);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          try {
            this.nativeStartSecondPage(want, myCall);
          } catch (err) {
            reject(err as BusinessError);
          }
        });
      });
    return p;
  }

  startUIAbility(want: Want): Promise<AbilityResult> {
    let p: Promise<AbilityResult> =
      new Promise<AbilityResult>((resolve: (data: AbilityResult) => void, reject: (err: BusinessError) => void): void => {
        let myCall: AsyncCallbackWrapper<AbilityResult> = new AsyncCallbackWrapper<AbilityResult>(
          (err: BusinessError | null, data: AbilityResult | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as AbilityResult);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeStartUIAbility(want, myCall);
        });
      });
    return p;
  }
}

