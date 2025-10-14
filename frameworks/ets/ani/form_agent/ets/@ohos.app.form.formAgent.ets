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

import { BusinessError, AsyncCallback } from '@ohos.base';
import Want from '@ohos.app.ability.Want';

export default class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

export namespace formAgent {
  loadLibrary("form_agent_ani.z")

  export native function nativeRequestPublishForm(want: Want, callback: AsyncCallbackWrapper<string>): void;
  export native function checkWantParam(want: Want): void;

  export function requestPublishForm(want: Want, callback: AsyncCallback<string>): void {
    checkWantParam(want);
    let myCall = new AsyncCallbackWrapper<string>(callback);
    taskpool.execute((): void => {
      formAgent.nativeRequestPublishForm(want, myCall);
    });
  }

  export function requestPublishForm(want: Want): Promise<string> {
    checkWantParam(want);
    let publishFormPromise: Promise<string> =
      new Promise<string>((resolve: (data: string) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<string>((err: BusinessError | null, data: string | undefined) => {
          if (err == null || err.code == 0) {
            resolve(data as string);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          formAgent.nativeRequestPublishForm(want, myCall);
        });
      });
    return publishFormPromise;
  }
}