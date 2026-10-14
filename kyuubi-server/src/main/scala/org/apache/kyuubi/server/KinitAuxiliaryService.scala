/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kyuubi.server

import java.io.IOException
import java.util.concurrent.TimeUnit

import org.apache.hadoop.security.UserGroupInformation

import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.service.AbstractService
import org.apache.kyuubi.util.{KyuubiHadoopUtils, ThreadUtils}

/**
 * A service that keeps the Kerberos credentials of the Kyuubi server process fresh by
 * re-logining from the keytab in-process.
 *
 * Unlike periodically running the external `kinit -kt` command, it never reads or rewrites
 * the local Kerberos credentials cache (ccache) file, so neither this service nor other
 * components on the host that rely on the same cache are affected by it.
 */
class KinitAuxiliaryService() extends AbstractService("KinitAuxiliaryService") {

  private val executor = ThreadUtils.newDaemonSingleThreadScheduledExecutor(getName)

  private var renewalInterval: Long = _
  private var renewalMaxAttempts: Int = _
  @volatile private var renewalAttempts: Int = _

  private var renewalTask: Runnable = _

  override def initialize(conf: KyuubiConf): Unit = {
    if (UserGroupInformation.isSecurityEnabled) {
      val keytab = conf.get(KyuubiConf.SERVER_KEYTAB)
      val principal = conf.get(KyuubiConf.SERVER_PRINCIPAL)
        .map(KyuubiHadoopUtils.getServerPrincipal)
      renewalInterval = conf.get(KyuubiConf.KINIT_INTERVAL)
      renewalMaxAttempts = conf.get(KyuubiConf.KINIT_MAX_ATTEMPTS)

      require(keytab.nonEmpty && principal.nonEmpty, "principal or keytab is missing")
      if (conf.get(KyuubiConf.ENGINE_DO_AS_ENABLED) &&
        conf.get(KyuubiConf.SESSION_LOCAL_DIR_ALLOW_LIST).isEmpty) {
        warn(s"User impersonation is enabled, but ${KyuubiConf.SESSION_LOCAL_DIR_ALLOW_LIST}" +
          " is unset. We strongly recommend to configure the allowed local dir list" +
          " to exclude any credential including keytab.")
      }
      UserGroupInformation.loginUserFromKeytab(principal.get, keytab.get)
      renewalTask = new Runnable {
        override def run(): Unit = {
          try {
            UserGroupInformation.getLoginUser.checkTGTAndReloginFromKeytab()
            renewalAttempts = 0
            debug("Successfully checked and renewed the Kerberos credentials from keytab")
            executor.schedule(this, renewalInterval, TimeUnit.MILLISECONDS)
          } catch {
            case e: IOException =>
              if (renewalAttempts >= renewalMaxAttempts) {
                error(
                  s"Failed to renew the Kerberos credentials from keytab after" +
                    s" $renewalAttempts attempts, will exit...",
                  e)
                System.exit(-1)
              }
              renewalAttempts += 1
              executor.submit(this)
          }
        }
      }
    }
    super.initialize(conf)
  }

  override def start(): Unit = {
    super.start()
    if (UserGroupInformation.isSecurityEnabled) {
      executor.submit(renewalTask)
    }
  }

  override def stop(): Unit = {
    super.stop()
    executor.shutdown()
    try {
      executor.awaitTermination(10, TimeUnit.SECONDS)
    } catch {
      case _: InterruptedException =>
    }
  }
}
