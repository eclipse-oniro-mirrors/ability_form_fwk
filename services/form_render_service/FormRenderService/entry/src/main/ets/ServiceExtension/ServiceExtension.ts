/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

import type rpc from '@ohos.rpc';
import ServiceExtensionAbility from '@ohos.app.ability.ServiceExtensionAbility';
import Want from '@ohos.app.ability.Want';

export default class ServiceExtension extends ServiceExtensionAbility {
  onCreate(want: Want): void {
    console.log('[FormRender] onCreate');
  }

  onRequest(want: Want, startId: number): void {
    console.log('[FormRender] onRequest');
  }

  onConnect(want: Want): rpc.RemoteObject | Promise<rpc.RemoteObject> {
    console.log('[FormRender] onConnect');
    return undefined;
  }

  onDisconnect(want: Want): void | Promise<void> {
    console.log('[FormRender] onDisconnect');
  }

  onDestroy(): void {
    console.log('[FormRender] onDestroy');
  }
}