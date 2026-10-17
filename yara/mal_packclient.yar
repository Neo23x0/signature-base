import "pe"

rule MAL_PackClient_Core_Sep26_1 {
   meta:
      description = "Detects the PackClient Core DLL using Core exports and plugin interface strings"
      author = "Ivan Immanuel Shaji"
      reference = "https://ivanimmanuel-dev.github.io/PackClient/"
      date = "2026-09-10"
      hash1 = "4de6ef8647fb4b599966a233740cb0514d1e71b8019a1a1792ed7e1e514edf1c"
      score = 80
      id = "6306ab29-c957-5078-967b-574cce6b60d5"
   strings:
      $core_name = "PackClientCore.dll" ascii
      $core_run = "PackClientDll_Run" ascii
      $core_alloc = "PackClient_AllocStoredPluginImageW" ascii

      $plugin_store = "PackMonitorClient.PluginStore.v1" ascii
      $plugin_feature = "PackPlugin_GetFeatureId" ascii
      $plugin_registry = "PackPlugin.Registry.dll" wide
      $plugin_browser = "PackPlugin_BrowserMgr_TryHandleExtRemote" ascii
   condition:
      uint16(0) == 0x5A4D and pe.is_pe and
      all of ($core_*) and
      3 of ($plugin_*)
}
