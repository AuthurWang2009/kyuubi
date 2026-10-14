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

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.Arrays

import scala.util.Try

import org.apache.hadoop.security.UserGroupInformation

import org.apache.kyuubi.KerberizedTestHelper
import org.apache.kyuubi.config.KyuubiConf
import org.apache.kyuubi.service.ServiceState

class KinitAuxiliaryServiceSuite extends KerberizedTestHelper {

  test("non secured kinit service") {
    val service = new KinitAuxiliaryService()
    assert(service.getServiceState === ServiceState.LATENT)
    service.initialize(KyuubiConf())
    assert(service.getServiceState === ServiceState.INITIALIZED)
    service.start()
    assert(service.getServiceState === ServiceState.STARTED)
    service.stop()
    assert(service.getServiceState === ServiceState.STOPPED)
  }

  test("secured kinit service") {
    tryWithSecurityEnabled {
      val service = new KinitAuxiliaryService()
      val conf = KyuubiConf()
      val e = intercept[IllegalArgumentException](service.initialize(conf))
      assert(e.getMessage === "requirement failed: principal or keytab is missing")
      conf.set(KyuubiConf.SERVER_PRINCIPAL, testPrincipal)
        .set(KyuubiConf.SERVER_KEYTAB, testKeytab)
        .set(KyuubiConf.KINIT_INTERVAL, 0L)
      service.initialize(conf)
      assert(UserGroupInformation.getCurrentUser.hasKerberosCredentials)
      assert(UserGroupInformation.getCurrentUser.isFromKeytab)
      service.start()
      assert(service.getServiceState === ServiceState.STARTED)
      service.stop()
      assert(service.getServiceState === ServiceState.STOPPED)
    }
  }

  test("renewing via external kinit corrupts the shared credentials cache") {
    assume(isKinitAvailable, "no kinit binary on this host")
    tryWithSecurityEnabled {
      val sharedCache = File.createTempFile("kyuubi-krb5cc", null)
      sharedCache.deleteOnExit()
      val otherComponentTickets = "tickets of other components".getBytes(StandardCharsets.UTF_8)
      Files.write(sharedCache.toPath, otherComponentTickets)

      // the renewal "succeeds" from the old implementation's point of view
      assert(renewViaExternalKinit(sharedCache) === 0)
      // ... yet it has rewritten the cache the other components depend on
      assert(!Arrays.equals(Files.readAllBytes(sharedCache.toPath), otherComponentTickets))

      // and once the shared cache location itself is broken, the external-kinit
      // mechanism cannot renew at all -- the condition the previous code answered
      // with immediate retries up to kyuubi.kinit.max.attempts and then System.exit
      val brokenCacheLocation = new File(sharedCache.getParentFile, "missing/krb5cc")
      assert(renewViaExternalKinit(brokenCacheLocation) !== 0)
    }
  }

  test("in-process renewal succeeds without touching the shared credentials cache") {
    tryWithSecurityEnabled {
      val sharedCache = File.createTempFile("kyuubi-krb5cc", null)
      sharedCache.deleteOnExit()
      val otherComponentTickets = "tickets of other components".getBytes(StandardCharsets.UTF_8)
      Files.write(sharedCache.toPath, otherComponentTickets)

      val service = new KinitAuxiliaryService()
      val conf = KyuubiConf()
      conf.set(KyuubiConf.SERVER_PRINCIPAL, testPrincipal)
        .set(KyuubiConf.SERVER_KEYTAB, testKeytab)
        .set(KyuubiConf.KINIT_INTERVAL, 0L)
      service.initialize(conf)
      service.start()
      assert(service.getServiceState === ServiceState.STARTED)
      // renewal works, and the credentials are sourced from the keytab rather than
      // from any cache
      val loginUser = UserGroupInformation.getLoginUser
      assert(loginUser.isFromKeytab)
      assert(loginUser.hasKerberosCredentials)

      // where renewing via external kinit rewrites the shared cache (see the test
      // above), in-process renewal leaves it untouched across continuous cycles
      val renewalWindowMs = 500
      Thread.sleep(renewalWindowMs)
      assert(Arrays.equals(Files.readAllBytes(sharedCache.toPath), otherComponentTickets))

      // and changes of the local cache while the server renews do not affect it
      // either: neither a rewrite by another principal nor a destroyed cache
      Files.write(
        sharedCache.toPath,
        "rewritten tickets of another principal".getBytes(StandardCharsets.UTF_8))
      Thread.sleep(renewalWindowMs)
      Files.write(sharedCache.toPath, Array.empty[Byte])
      Thread.sleep(renewalWindowMs)
      assert(loginUser.isFromKeytab)
      assert(loginUser.hasKerberosCredentials)
      loginUser.checkTGTAndReloginFromKeytab()
      assert(loginUser.hasKerberosCredentials)

      service.stop()
      assert(service.getServiceState === ServiceState.STOPPED)
    }
  }

  // Reference of the core behavior the previous KinitAuxiliaryService implementation
  // used for renewal: run `kinit -kt` as an external process. The child process
  // inherited the host environment, so it rewrote whatever cache KRB5CCNAME points
  // to and required that location to be writable. The cache location is pinned
  // here explicitly to observe both properties.
  private def renewViaExternalKinit(cache: File): Int = {
    val kinitProc = new ProcessBuilder("kinit", "-kt", testKeytab, testPrincipal).inheritIO()
    kinitProc.environment().put("KRB5CCNAME", cache.getAbsolutePath)
    kinitProc.environment().put("KRB5_CONFIG", krb5ConfPath)
    kinitProc.start().waitFor()
  }

  private def isKinitAvailable: Boolean = {
    Try(new ProcessBuilder("sh", "-c", "command -v kinit >/dev/null 2>&1")
      .start().waitFor() == 0).getOrElse(false)
  }
}
