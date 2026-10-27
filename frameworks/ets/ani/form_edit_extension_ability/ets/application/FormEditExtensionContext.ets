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

export class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

const ERROR_CODE_INVALID_COLOR_VALUE = 16501026;
const ERROR_MSG_INVALID_COLOR_VALUE = 'Invalid color value';
const COLOR_LEN_RGB = 7;
const COLOR_LEN_ARGB = 9;

function isValidColorFormat(color: string): boolean {
  if (typeof color !== 'string' ||
      (color.length !== COLOR_LEN_RGB && color.length !== COLOR_LEN_ARGB) ||
      color[0] !== '#') {
    return false;
  }
  for (let i = 1; i < color.length; i++) {
    let c = color[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      return false;
    }
  }
  return true;
}

export default class FormEditExtensionContext extends UIExtensionContext {

  native nativeStartSecondPage(want: Want, callback: AsyncCallbackWrapper<AbilityResult>): void;

  native nativeStartUIAbility(want: Want, callback: AsyncCallbackWrapper<AbilityResult>): void;

  native nativeSetWindowBackgroundColor(color: string): void;

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

  async setWindowBackgroundColor(color: string): Promise<void> {
    if (!isValidColorFormat(color)) {
      throw { code: ERROR_CODE_INVALID_COLOR_VALUE, message: ERROR_MSG_INVALID_COLOR_VALUE } as BusinessError;
    }
    await taskpool.execute((): void => {
      this.nativeSetWindowBackgroundColor(color);
    });
  }
}

