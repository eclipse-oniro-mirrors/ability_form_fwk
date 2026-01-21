/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import ExtensionContext from 'application.ExtensionContext';
import { BusinessError, AsyncCallback } from '@ohos.base';
import type Want from '@ohos.app.ability.Want';
import { ConnectOptions } from 'ability.connectOptions';

class AsyncCallbackWrapper<T, E = void> {
  private myFun_: AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun: AsyncCallback<T, E>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined): void {
    this.myFun_(err, data);
  }
}

class Cleaner {
  public ptr: long = 0;
  constructor(ptr: long) {
    this.ptr = ptr;
  }
  native clean(): void;
}
export function callback(cleaner: Cleaner): void {
  cleaner.clean();
}
let destroyRegister = new FinalizationRegistry<Cleaner>(callback);
let unregisterToken = new object();

export default class LiveFormExtensionContext extends ExtensionContext {
  constructor(context: long) {
    if (this.nativeEtsContext == 0) {
      this.nativeEtsContext = context;
    }
    this.registerCleaner(this.nativeEtsContext);
  }

  registerCleaner(ptr: long): void {
    this.cleaner = new Cleaner(ptr);
    destroyRegister.register(this, this.cleaner!, unregisterToken);
  }

  unregisterCleaner(): void {
    destroyRegister.unregister(unregisterToken);
  }

  nativeEtsContext: long = 0;
  private cleaner: Cleaner | null = null;

  native nativeStartAbilityByLiveForm(want: Want, formId: string, callback: AsyncCallbackWrapper<void>): void;
  native nativeConnectServiceExtensionAbility(want: Want, options: ConnectOptions): long;
  native nativeDisconnectServiceExtensionAbility(connectionId: long, callback: AsyncCallbackWrapper<void>): void;

  startAbilityByLiveForm(want: Want): Promise<void> {
    let p: Promise<void> = new Promise<void>((
      resolve: (data: undefined) => void,
      reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          try {
            this.nativeStartAbilityByLiveForm(want, "", myCall);
          } catch (err: BusinessError) {
            reject(err);
          }
        });
      });
    return p;
  }

  connectServiceExtensionAbility(want: Want, options: ConnectOptions): long {
    return this.nativeConnectServiceExtensionAbility(want, options);
  }

  disconnectServiceExtensionAbility(connectionId: long): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err == null || err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          try {
            this.nativeDisconnectServiceExtensionAbility(connectionId, myCall);
          } catch (err: BusinessError) {
            reject(err);
          }
        });
      });
    return p;
  }
}
