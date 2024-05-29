#!/usr/bin/python3

# RPC implementation
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import rpcrt

# Others
import time, argparse, sys, re, datetime, base64
from impacket.dcerpc.v5.ndr import NULL
from impacket import uuid
from io import StringIO

##################################################################
### [MS-RPCE]-C706 = Remote Procedure Call Protocol Extensions ###
###                   Interface = EPMAPPER                     ###
##################################################################

from impacket.dcerpc.v5 import epm

def listEndpoints(ip):
  ###
  # Does not require administrative rights
  ###

  # Connect to the interface
  rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
  dce = rpctransport.get_dce_rpc()
  dce.connect()
  dce.bind(uuid.uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0')))

  # Query methods of the interface
  entries = []
  entry_handle = epm.ept_lookup_handle_t()
  while True:
    request = epm.ept_lookup()
    request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
    request['object'] = NULL
    request['Ifid'] = NULL
    request['vers_option'] = epm.RPC_C_VERS_ALL
    request['entry_handle'] = entry_handle
    request['max_ents'] = 500

    res = dce.request(request)

    for i in range(res['num_ents']):
      tmpEntry = {}
      entry = res['entries'][i]
      tmpEntry['object'] = entry['object']
      tmpEntry['annotation'] = b''.join(entry['annotation'])
      tmpEntry['tower'] = epm.EPMTower(b''.join(entry['tower']['tower_octet_string']))
      entries.append(tmpEntry)

    entry_handle = res['entry_handle']
    if entry_handle.isNull():
        break

  endpoints = {}
  # Let's groups the UUIDS
  for entry in entries:
    binding = epm.PrintStringBinding(entry['tower']['Floors'])
    tmpUUID = str(entry['tower']['Floors'][0])
    if (tmpUUID in endpoints) is not True:
        endpoints[tmpUUID] = {}
        endpoints[tmpUUID]['Bindings'] = list()
    if uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
        endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[uuid.uuidtup_to_bin(uuid.string_to_uuidtup(tmpUUID))[:18]]
    else:
        endpoints[tmpUUID]['EXE'] = 'N/A'
    endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
    endpoints[tmpUUID]['Bindings'].append(binding)

    if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
        endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
    else:
        endpoints[tmpUUID]['Protocol'] = "N/A"

  for endpoint in list(endpoints.keys()):
    print("[+] Protocol: %s " % endpoints[endpoint]['Protocol'])
    print("[+] Provider: %s " % endpoints[endpoint]['EXE'])
    print("[+] UUID    : %s %s" % (endpoint, endpoints[endpoint]['annotation']))
    print("[+] Bindings: ")
    for binding in endpoints[endpoint]['Bindings']:
        print("\t\t%s" % binding)
    print("")

  return endpoints

def searchUnauthBindings(ip):
  print("[+] Enumerate endpoints through EPMAPPER interface")
  originalSTDOUT = sys.stdout
  sys.stdout = StringIO()
  endpoints = listEndpoints(ip)
  sys.stdout = originalSTDOUT

  print("[+] Searching unauthenticated bindings")
  for endpoint in list(endpoints.keys()):
    print(f"[+] Testing {endpoint} for {endpoints[endpoint]['Protocol']}")
    unauthBinding = False
    for binding in endpoints[endpoint]['Bindings']:
      if (not binding.startswith("ncalrpc:")):
        try:
          rpctransport = transport.DCERPCTransportFactory(binding)
          remoteName = rpctransport.getRemoteName()
          if (remoteName.startswith("\\\\")):
            rpctransport.setRemoteName(remoteName[2:])
            rpctransport.setRemoteHost(remoteName[2:])
          dce = rpctransport.get_dce_rpc()
          dce.connect()
          ifId, version = endpoint.split(" ")
          version = version[1:]
          dce.bind(uuid.uuidtup_to_bin((ifId, version)))
          unauthBinding = True
          print(f"\t[+] Found unauthenticated binding: {binding}")
        except Exception as e:
          if (str(e).find("rpc_s_access_denied") != -1):
            print(f"\t[-] Access denied for binding {binding}")
          else:
            print(f"\t[-] Got error for binding {binding}: {str(e)}")
    if (unauthBinding == False):
      print("\t[-] No unauthenticated binding found")

def getOSArch(ip):
  ###
  # Does not require administrative rights
  ###

  print("[+] Getting Windows OS architecture (x86/x64)")

  # Connect to the interface
  rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
  dce = rpctransport.get_dce_rpc()
  dce.connect()
  NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
  try:
    dce.bind(uuid.uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0')), transfer_syntax = NDR64Syntax)
  except Exception as e:
    if str(e).find('syntaxes_not_supported') >= 0:
      print('\t[+] %s is 32-bit' % ip)
    else:
      print("\t[-] Error: " + str(e))
      pass
  else:
    print('\t[+] %s is 64-bit' % ip)

###########################################################
### [MS-SCMR] = Service Control Manager Remote Protocol ###
###                 Interface = SVCCTL                  ###
###########################################################

from impacket.dcerpc.v5 import scmr

def RCESVCCTL(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Executing command")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    SERVICENAME = "MyService" + "\x00"
    res = scmr.hROpenSCManagerW(dce)
    svcmHandle = res['lpScHandle']
    if svcmHandle != 0:
      # First we try to open the service in case it exists.
      # If it does, we remove it.
      try:
          svc = scmr.hROpenServiceW(dce, svcmHandle, SERVICENAME)
      except Exception as e:
          if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') >= 0:
              pass
          else:
              raise e
      else:
          # It exists, remove it
          scmr.hRDeleteService(dce, svc['lpServiceHandle'])
          scmr.hRCloseServiceHandle(dce, svc['lpServiceHandle'])

      # Create the service
      COMMAND = 'C:\\Windows\\System32\\cmd.exe /c %s\x00' % (cmd)
      res = scmr.hRCreateServiceW(dce, svcmHandle, SERVICENAME, SERVICENAME,
                                        lpBinaryPathName = COMMAND, dwStartType = scmr.SERVICE_DEMAND_START)
      svcHandle = res['lpServiceHandle']
      if svcHandle != 0:
        # Start service
        try:
          scmr.hRStartServiceW(dce, svcHandle)
        except Exception as e:
          if str(e).find('ERROR_SERVICE_REQUEST_TIMEOUT') >= 0:
            # The BINARY_PATH_NAME which contain the system cmd to execute
            # Will not resond to the Service Manager as a normal service should
            # Thus, the Service Manager will raise this error But It is normal
            pass
          else:
            raise e
        # Wait service stop
        DONE = False
        while not DONE:
          res = scmr.hRQueryServiceStatus(dce, svcHandle)
          status = res['lpServiceStatus']['dwCurrentState']
          if status == scmr.SERVICE_STOPPED:
            DONE = True
          else:
            time.sleep(2)
        # Delete service
        try:
            scmr.hRDeleteService(dce, svcHandle)
        except:
            pass
        scmr.hRCloseServiceHandle(dce, svcHandle)
      scmr.hRCloseServiceHandle(dce, svcmHandle)

    print ("\t[+] Command executed")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def startService(ip, user, pwd, domain, lmhash, nthash, aesKey, serviceName, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Starting '%s' service on remote host" % serviceName)

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    SERVICENAME = serviceName + "\x00"
    res = scmr.hROpenSCManagerW(dce)
    svcmHandle = res['lpScHandle']
    if svcmHandle == 0:
      print("\t[-] Failed to get handle on Service Manager")
      return False
    else:
      svc = scmr.hROpenServiceW(dce, svcmHandle, SERVICENAME)
      svcHandle = svc['lpServiceHandle']
      res = scmr.hRQueryServiceStatus(dce, svcHandle)
      if res['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
        print("\t[+] Service is already running")
      elif res['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
        res = scmr.hRQueryServiceConfigW(dce, svcHandle)
        if res['lpServiceConfig']['dwStartType'] == 0x4:
          print("\t[+] Service is disabled. Enabling It")
          scmr.hRChangeServiceConfigW(dce, svcHandle, dwStartType = 0x3)
        scmr.hRStartServiceW(dce, svcHandle)
        time.sleep(1)
        print("\t[+] Service started")
      else:
        print('\t[-] Unknown service state 0x%x - Aborting' % res['CurrentState'])
        return False
    return True
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")
    return False

def listServices(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  # Services runned by domain users => Password stored into LSA Secrets
  ###

  print("[+] Listing services on remote host")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    res = scmr.hROpenSCManagerW(dce)
    svcmHandle = res['lpScHandle']
    if svcmHandle == 0:
      print("\t[-] Failed to get handle on Service Manager")
      return
    else:
      res = scmr.hREnumServicesStatusW(dce, svcmHandle, dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS, dwServiceState = scmr.SERVICE_STATE_ALL)
      for i in range(len(res)):
        try:
          svcName = res[i]['lpServiceName'][:-1]
          svc = scmr.hROpenServiceW(dce, svcmHandle, res[i]['lpServiceName'][:-1])
          svcHandle = svc['lpServiceHandle']
          svcConf = scmr.hRQueryServiceConfigW(dce, svcHandle)
          svcUser = svcConf['lpServiceConfig']['lpServiceStartName'][:-1]
          print(f"\tService '{svcName}' found for {svcUser}")
        except Exception as e:
            if 'rpc_s_access_denied' not in str(e):
              print("\t[-] Exception querying service '%s': %s" % (res[i]['lpServiceName'][:-1], str(e)))
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

############################################################
### [MS-TSCH] = Task Scheduler Service Remoting Protocol ###
###       Interfaces = ITaskSchedulerService / ATSVC     ###
############################################################

from impacket.dcerpc.v5 import tsch

def xml_escape(data):
  replace_table = {
          "&": "&amp;",
          '"': "&quot;",
          "'": "&apos;",
          ">": "&gt;",
          "<": "&lt;",
          }
  return ''.join(replace_table.get(c, c) for c in data)

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c %s</Arguments>
    </Exec>
  </Actions>
</Task>
        """

def RCEITaskSchedulerService(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Executing command")

  try:
    # Connect to the interface ITaskSchedulerService
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if not unauthBinding:
      dce.set_credentials(*rpctransport.get_credentials())
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    TASKNAME = '\\MyTask'
    XML = XML_TEMPLATE % (" ".join([xml_escape(x) for x in cmd.split(" ")]))
    DONE = False
    tsch.hSchRpcRegisterTask(dce, TASKNAME, XML, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
    tsch.hSchRpcRun(dce, TASKNAME)
    while not DONE:
        res = tsch.hSchRpcGetLastRunInfo(dce, TASKNAME)
        if res['pLastRuntime']['wYear'] != 0:
            DONE = True
        else:
            time.sleep(2)
    tsch.hSchRpcDelete(dce, TASKNAME)

    print ("\t[+] Command executed")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def listScheduledTasks(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  # Scheduled Tasks with Logon Type = Password => Password stored into Vault Credential Manager
  ###

  print("[+] Listing scheduled tasks on remote host")

  try:
    # Connect to the interface ITaskSchedulerService
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if not unauthBinding:
      dce.set_credentials(*rpctransport.get_credentials())
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('86D35949-83C9-4044-B424-DB363231FD0C', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    # Blacklisted folders (Default ones)
    blacklist = [u'Microsoft\x00']
    # Start with the root folder
    folders = ['\\']
    tasks = []
    schtaskusers = []
    # Get root folder
    res = tsch.hSchRpcEnumFolders(dce, '\\')
    for item in res['pNames']:
      data = item['Data']
      if data not in blacklist:
          folders.append('\\' + data)
    # Enumerate folders
    # Subfolders not supported yet
    for folder in folders:
      res = tsch.hSchRpcEnumTasks(dce, folder)
      for item in res['pNames']:
        data = item['Data']
        if folder != '\\':
            # Make sure to strip the null byte
            tasks.append(folder[:-1] + '\\' + data)
        else:
            tasks.append(folder + data)
    for task in tasks:
      res = tsch.hSchRpcRetrieveTask(dce, task)
      userInfoXML = res['pXml']
      SIDString = userInfoXML.split("<UserId>")[1].split("</UserId>")[0]
      try:
        logonType = userInfoXML.split("<LogonType>")[1].split("</LogonType>")[0]
      except:
        logonType = "<Empty>"
      originalSTDOUT = sys.stdout
      sys.stdout = StringIO()
      login = SIDToName(ip, user, pwd, domain, lmhash, nthash, aesKey, SIDString)
      sys.stdout = originalSTDOUT
      print(f"\tScheduled task '{task}' found for {login} (Logon type = {logonType})")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

from impacket.dcerpc.v5 import atsvc

def RCEATSVC(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Executing command")

  try:
    # Connect to the interface ATSVC
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if not unauthBinding:
      dce.set_credentials(*rpctransport.get_credentials())
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    serverName = atsvc.ATSVC_HANDLE()
    serverName['Data'] = "\\%s\x00" % ip
    AtInfo = atsvc.AT_INFO()
    AtInfo['JobTime'] = 1
    AtInfo['DaysOfMonth'] = 0xffffffff
    AtInfo['DaysOfWeek'] = 0xff
    AtInfo['Flags'] = 0b00010100
    AtInfo['Command'] = "cmd.exe /c " + cmd + "\x00"
    res = atsvc.hNetrJobAdd(dce, serverName, AtInfo)
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

#############################################################################
### [MS-DCOM] = Distributed Component Object Model (DCOM) Remote Protocol ###
###        Interface = IRemoteSCMActivator for creating COM objects       ###
#############################################################################

from impacket.dcerpc.v5 import dcomrt

###   COM objects                                                         ###
###   CLSID = 9BA05972-F6A8-11CF-A442-00A0C90A8F39 for ShellWindows       ###
###   CLSID = C08AFD90-F2A1-11D1-8455-00A0C91F3880 for ShellBrowserWindow ###
###   CLSID = 49B2791A-B1AE-4C90-9B8E-E860BA07F889 for MMC20              ###

from impacket.dcerpc.v5.dcom import oaut

def getInterface(interface, res):
  objRefType = dcomrt.OBJREF(b''.join(res))['flags']
  objRef = None
  if objRefType == dcomrt.FLAGS_OBJREF_CUSTOM:
    objRef = dcomrt.OBJREF_CUSTOM(b''.join(res))
  elif objRefType == dcomrt.FLAGS_OBJREF_HANDLER:
    objRef = dcomrt.OBJREF_HANDLER(b''.join(res))
  elif objRefType == dcomrt.FLAGS_OBJREF_STANDARD:
    objRef = dcomrt.OBJREF_STANDARD(b''.join(res))
  elif objRefType == dcomrt.FLAGS_OBJREF_EXTENDED:
    objRef = dcomrt.OBJREF_EXTENDED(b''.join(res))
  else:
    print("[-] Unknown OBJREF Type! 0x%x" % objRefType)

  return dcomrt.IRemUnknown2(dcomrt.INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'], oxid = objRef['std']['oxid'], oid = objRef['std']['oxid'], target = interface.get_target()))

def RCEDCOM1(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False):
  ###
  # Require administrative rights
  ###

  print("[+] Executing command")

  try:
    # Connect to the interface
    rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    scm = dcomrt.IRemoteSCMActivator(dce)

    # Create COM object
    COMMETHOD = "MMC20"
    if COMMETHOD == "ShellWindows":
      CLSID = uuid.string_to_bin('9BA05972-F6A8-11CF-A442-00A0C90A8F39')
    elif COMMETHOD == "ShellBrowserWindow":
      CLSID = uuid.string_to_bin('C08AFD90-F2A1-11D1-8455-00A0C91F3880')
    else:
      CLSID = uuid.string_to_bin('49B2791A-B1AE-4C90-9B8E-E860BA07F889')
    IID = uuid.string_to_bin('00020400-0000-0000-C000-000000000046') # IDispatch
    iInterface = scm.RemoteCreateInstance(CLSID, IID)
    # scm.RemoteCreateInstance(CLSID, IID):
    #   dce.bind(uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046', '0.0'))) # IRemoteSCMActivator
    #   ORPC call -> Get Object References (String bindings of the Object Exporter, IID, IPID, etc.)
    #   Build and return the ORPC interface based on Object References

    # Connect to the Object Exporter that expose the created COM object
    iMMC = oaut.IDispatch(iInterface)
    dcomrt.DCOMConnection.PORTMAPS[ip] = dce

    # Query the COM object
    dispParams = oaut.DISPPARAMS(None, False)
    dispParams['rgvarg'] = NULL
    dispParams['rgdispidNamedArgs'] = NULL
    dispParams['cArgs'] = 0
    dispParams['cNamedArgs'] = 0
    if COMMETHOD == 'ShellWindows':
      res = iMMC.GetIDsOfNames(('Item',))
      res = iMMC.Invoke(res[0], 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])
      iItem = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
      res = iItem.GetIDsOfNames(('Document',))
      res = iItem.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
      pQuit = None
    else:
      res = iMMC.GetIDsOfNames(('Document',))
      res = iMMC.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
      pQuit = iMMC.GetIDsOfNames(('Quit',))[0]

    iDocument = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
    if COMMETHOD == 'MMC20':
      res = iDocument.GetIDsOfNames(('ActiveView',))
      res = iDocument.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
      iActiveView = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
      pExecuteShellCommand = iActiveView.GetIDsOfNames(('ExecuteShellCommand',))[0]
      dispParams = oaut.DISPPARAMS(None, False)
      dispParams['rgdispidNamedArgs'] = NULL
      dispParams['cArgs'] = 4
      dispParams['cNamedArgs'] = 0
      arg0 = oaut.VARIANT(None, False)
      arg0['clSize'] = 5
      arg0['vt'] = oaut.VARENUM.VT_BSTR
      arg0['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg0['_varUnion']['bstrVal']['asData'] = "cmd.exe"
      arg1 = oaut.VARIANT(None, False)
      arg1['clSize'] = 5
      arg1['vt'] = oaut.VARENUM.VT_BSTR
      arg1['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg1['_varUnion']['bstrVal']['asData'] = 'C:\\windows\\system32'
      arg2 = oaut.VARIANT(None, False)
      arg2['clSize'] = 5
      arg2['vt'] = oaut.VARENUM.VT_BSTR
      arg2['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg2['_varUnion']['bstrVal']['asData'] = "/c " + cmd
      arg3 = oaut.VARIANT(None, False)
      arg3['clSize'] = 5
      arg3['vt'] = oaut.VARENUM.VT_BSTR
      arg3['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg3['_varUnion']['bstrVal']['asData'] = '7'
      dispParams['rgvarg'].append(arg3)
      dispParams['rgvarg'].append(arg2)
      dispParams['rgvarg'].append(arg1)
      dispParams['rgvarg'].append(arg0)
    else:
      res = iDocument.GetIDsOfNames(('Application',))
      res = iDocument.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
      iActiveView = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
      pExecuteShellCommand = iActiveView.GetIDsOfNames(('ShellExecute',))[0]
      dispParams = oaut.DISPPARAMS(None, False)
      dispParams['rgdispidNamedArgs'] = NULL
      dispParams['cArgs'] = 5
      dispParams['cNamedArgs'] = 0
      arg0 = oaut.VARIANT(None, False)
      arg0['clSize'] = 5
      arg0['vt'] = oaut.VARENUM.VT_BSTR
      arg0['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg0['_varUnion']['bstrVal']['asData'] = "cmd.exe"
      arg1 = oaut.VARIANT(None, False)
      arg1['clSize'] = 5
      arg1['vt'] = oaut.VARENUM.VT_BSTR
      arg1['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg1['_varUnion']['bstrVal']['asData'] = "/c " + cmd
      arg2 = oaut.VARIANT(None, False)
      arg2['clSize'] = 5
      arg2['vt'] = oaut.VARENUM.VT_BSTR
      arg2['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg2['_varUnion']['bstrVal']['asData'] = 'C:\\windows\\system32'
      arg3 = oaut.VARIANT(None, False)
      arg3['clSize'] = 5
      arg3['vt'] = oaut.VARENUM.VT_BSTR
      arg3['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg3['_varUnion']['bstrVal']['asData'] = ''
      arg4 = oaut.VARIANT(None, False)
      arg4['clSize'] = 5
      arg4['vt'] = oaut.VARENUM.VT_BSTR
      arg4['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
      arg4['_varUnion']['bstrVal']['asData'] = '0'
      dispParams['rgvarg'].append(arg4)
      dispParams['rgvarg'].append(arg3)
      dispParams['rgvarg'].append(arg2)
      dispParams['rgvarg'].append(arg1)
      dispParams['rgvarg'].append(arg0)

    iActiveView.Invoke(pExecuteShellCommand, 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])

    dispParams = oaut.DISPPARAMS(None, False)
    dispParams['rgvarg'] = NULL
    dispParams['rgdispidNamedArgs'] = NULL
    dispParams['cArgs'] = 0
    dispParams['cNamedArgs'] = 0
    iMMC.Invoke(pQuit, 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])

    print ("\t[+] Command executed")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

###   COM objects                                                         ###
###   CLSID = 8BC3F05E-D86B-11D0-A075-00C04FB68820 for WbemLevel1Login    ###

from impacket.dcerpc.v5.dcom import wmi

def RCEDCOM2(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False):
  ###
  # Require administrative rights
  ###

  print("[+] Executing command")

  try:
    # Connect to the interface
    rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    scm = dcomrt.IRemoteSCMActivator(dce)

    # Create COM object
    CLSID = uuid.string_to_bin('8BC3F05E-D86B-11D0-A075-00C04FB68820') # WbemLevel1Login
    IID = uuid.uuidtup_to_bin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0')) # IWbemLevel1Login
    iInterface = scm.RemoteCreateInstance(CLSID, IID)
    # scm.RemoteCreateInstance(CLSID, IID):
    #   dce.bind(uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046', '0.0'))) # IRemoteSCMActivator
    #   ORPC call -> Get Object References (String bindings of the Object Exporter, IID, IPID, etc.)
    #   Build and return the ORPC interface based on Object References

    # Connect to the Object Exporter that expose the created COM object
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    dcomrt.DCOMConnection.PORTMAPS[ip] = dce

    # Query the COM object
    iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
    iWbemLevel1Login.RemRelease()
    win32Process, _ = iWbemServices.GetObject('Win32_Process')
    win32Process.Create("cmd.exe /c " + cmd, "C:\\", None)

    print ("\t[+] Command executed")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

################################################################################
### [MS-TSTS] = Terminal Services Terminal Server Runtime Interface Protocol ###
###      Interfaces = TermSrvEnumeration / TermSrvSession / LegacyAPI        ###
################################################################################

from impacket.dcerpc.v5 import tsts

def listRDSSessions(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None):
  ###
  # Does not require administrative rights
  # BUT "However, only sessions for which the caller has WINSTATION_QUERY permission are enumerated. The method checks whether the caller has WINSTATION_QUERY permission (section 3.1.1) by setting it as the Access Request mask, and skips the sessions for which the caller does not have the permission."
  #   https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/1a7d5d1d-1ce5-448f-bb4a-c79741982edb
  # Notable states with Session Tokens/Reusable creds in LSASS
  # Active + Unlocked -> User is logged in
  # Active + Locked -> User locked the session
  # Disconnected + Unlocked -> User switched session
  ###

  print("[+] Listing Remote Desktop Services sessions")

  try:
    # Connect to the interface TermSrvEnumeration
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\LSM_API_service]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.bind(uuid.uuidtup_to_bin(('88143fd0-c28d-4b2b-8fef-8d882f6a9390', '1.0')))

    # Query methods of the interface
    handle = tsts.hRpcOpenEnum(dce)
    rSessions = tsts.hRpcGetEnumResult(dce, handle, Level = 1)['ppSessionEnumResult']
    tsts.hRpcCloseEnum(dce, handle)

    # Connect to the interface TermSrvSession
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\LSM_API_service]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    dce.bind(uuid.uuidtup_to_bin(('484809d6-4239-471b-b5bc-61df8c23ac48', '1.0')))

    # Query methods of the interface
    desktopStates = {
        'WTS_SESSIONSTATE_UNKNOWN': 'Unknown',
        'WTS_SESSIONSTATE_LOCK'   : 'Locked',
        'WTS_SESSIONSTATE_UNLOCK' : 'Unlocked',
    }
    for i in rSessions:
        sess = i['SessionInfo']['SessionEnum_Level1']
        sessID = sess['SessionId']
        sessName = sess['Name'] if sess['Name'] != '' else 'None'
        sessState = tsts.enum2value(tsts.WINSTATIONSTATECLASS, sess['State']).split('_')[-1]
        data = tsts.hRpcGetSessionInformationEx(dce, sessID)
        sessFlags = desktopStates[tsts.enum2value(tsts.SESSIONFLAGS, data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['SessionFlags'])]
        sessDomain = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DomainName']
        sessUsername = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['UserName']
        if (sessDomain != '' and sessUsername != ''):
            sessLogin = f"{sessDomain}\\{sessUsername}"
        elif (sessDomain == '' and sessUsername == ''):
            sessLogin = 'None'
        elif (sessDomain == ''):
            sessLogin = f".\\{sessUsername}"
        else:
            sessLogin = f"{sessDomain}\\None" # Should not happen
        sessConnectTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['ConnectTime']
        sessConnectTime = sessConnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if sessConnectTime.year > 1601 else 'None'
        sessDisconnectTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DisconnectTime']
        sessDisconnectTime = sessDisconnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if sessDisconnectTime.year > 1601 else 'None'
        sessLogonTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LogonTime']
        sessLastInputTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LastInputTime']
        print(f"\tSession ID = {sessID}\n\t\tSession Name = {sessName}\n\t\tSession Username = {sessLogin}\n\t\tSession State = {sessState}\n\t\tSession Desktop = {sessFlags}\n\t\tSession Connect Time = {sessConnectTime}\n\t\tSession Disconnect Time = {sessDisconnectTime}")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def listProcesses(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Listing running processes")

  try:
    # Connect to the interface LegacyAPI
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\Ctx_WinStation_API_service]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('5ca4a760-ebb1-11cf-8611-00a0245420ed', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    handle = tsts.hRpcWinStationOpenServer(dce)
    r = tsts.hRpcWinStationGetAllProcesses(dce, handle)
    if not len(r):
        return None
    for procInfo in r:
      print(f"\t{procInfo['ImageName']}\t{procInfo['UniqueProcessId']}\t{procInfo['SessionId']}\t{procInfo['pSid']}")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

##################################################
### [MS-SRVS] = Server Service Remote Protocol ###
###             Interface = SRVSVC             ###
##################################################

from impacket.dcerpc.v5 import srvs

def listSessions(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  # BUT will display only our session
  ###

  print("[+] Listing sessions on remote host")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\srvsvc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    res = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
    for session in res['InfoStruct']['SessionInfo']['Level10']['Buffer']:
      username = session['sesi10_username'][:-1]
      sourceIP = session['sesi10_cname'][:-1][2:]
      active = session['sesi10_time']
      idle = session['sesi10_idle_time']
      print(f"\t{username}\t{sourceIP}\t{active}\t{idle}")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

#######################################################
### [MS-WKST] = Workstation Service Remote Protocol ###
###               Interface = WKSSVC                ###
#######################################################

from impacket.dcerpc.v5 import wkst

def listLoggedIn(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights
  ###

  print("[+] Listing logged in users on remote host")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\wkssvc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    res = wkst.hNetrWkstaUserEnum(dce, 1)
    for session in res['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
      username = session['wkui1_username'][:-1]
      logonDomain = session['wkui1_logon_domain'][:-1]
      print(f"\t{logonDomain}\\{username} logged in")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

###################################################
### [MS-RRP] = Windows Remote Registry Protocol ###
###             Interface = WINREG              ###
###################################################

from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.dtypes import READ_CONTROL

regTypes = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
    5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD'}

def stripRootKey(dce, keyName):
  # Let's strip the root key
  try:
    rootKey = keyName.split('\\')[0]
    subKey = '\\'.join(keyName.split('\\')[1:])
  except Exception:
    raise Exception("Error parsing keyName '%s'" % keyName)
  if rootKey.upper() == 'HKLM':
    ans = rrp.hOpenLocalMachine(dce)
  elif rootKey.upper() == 'HKCU':
    ans = rrp.hOpenCurrentUser(dce)
  elif rootKey.upper() == 'HKCR':
    ans = rrp.hOpenClassesRoot(dce)
  elif rootKey.upper() == 'HKU':
    ans = rrp.hOpenUsers(dce)
  elif rootKey.upper() == 'HKCC':
    ans = rrp.hOpenCurrentConfig(dce)
  else:
    raise Exception("Invalid root key '%s'" % rootKey)
  hRootKey = ans['phKey']
  return hRootKey, subKey

def printKeyValues(dce, keyHandler, nbTab):
  i = 0
  while True:
    try:
      ans4 = rrp.hBaseRegEnumValue(dce, keyHandler, i)
      lp_value_name = ans4['lpValueNameOut'][:-1]
      if len(lp_value_name) == 0:
        lp_value_name = '(Default)'
      lp_type = ans4['lpType']
      lp_data = b''.join(ans4['lpData'])
      print('\t' * nbTab + lp_value_name + '\t' + regTypes.get(lp_type, 'KEY_NOT_FOUND') + '\t', end = ' ')
      parseData(lp_type, lp_data, nbTab + 1)
      i += 1
    except Exception as e:
      if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
        break
      else:
        raise e

def printAllSubkeysAndEntries(dce, keyName, keyHandler, nbTab):
  index = 0
  while True:
    try:
      subkey = rrp.hBaseRegEnumKey(dce, keyHandler, index)
      index += 1
      res = rrp.hBaseRegOpenKey(dce, keyHandler, subkey['lpNameOut'], samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
      newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
      print('\t' * nbTab + newKeyName)
      printKeyValues(dce, res['phkResult'], nbTab + 1)
      printAllSubkeysAndEntries(dce, newKeyName, res['phkResult'], nbTab + 1)
    except Exception as e:
      if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
        break
      elif str(e).find('access_denied') >= 0:
        print('\t' * nbTab + "[-] Cannot access subkey '%s', bypassing it" % subkey['lpNameOut'][:-1])
        continue
      elif str(e).find('rpc_x_bad_stub_data') >= 0:
        print('\t' * nbTab + "[-] Fault call, cannot retrieve value for '%s', bypassing it" % subkey['lpNameOut'][:-1])
        return
      else:
        raise e

def parseData(valueType, valueData, nbTab):
  from struct import unpack
  from impacket.structure import hexdump

  try:
    if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
      if type(valueData) is int:
        print('NULL')
      else:
        print("%s" % (valueData.decode('utf-16le')[:-1]))
    elif valueType == rrp.REG_BINARY:
      print('')
      hexdump(valueData, '\t' * nbTab)
    elif valueType == rrp.REG_DWORD:
      print("0x%x" % (unpack('<L', valueData)[0]))
    elif valueType == rrp.REG_QWORD:
      print("0x%x" % (unpack('<Q', valueData)[0]))
    elif valueType == rrp.REG_NONE:
      try:
        if len(valueData) > 1:
          print('')
          hexdump(valueData, '\t')
        else:
          print("NULL")
      except:
        print("NULL")
    elif valueType == rrp.REG_MULTI_SZ:
      print("%s" % (valueData.decode('utf-16le')[:-2]))
    else:
      print("Unknown Type 0x%x!" % valueType)
      hexdump(valueData)
  except Exception as e:
    print('Exception when printing reg value: %s' % str(e))
    pass

def extractKeys(cmd):
  # Regular expression to match words within single quotes and words without quotes
  pattern = r"'[^']*'|\S+"
  # Find all matches using the pattern
  words = re.findall(pattern, cmd)
  # Remove single quotes from extracted words
  words = [word.strip("'") for word in words]

  return words

def regCMD(ip, user, pwd, domain, lmhash, nthash, aesKey, cmd, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  # The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
  # BUT It can be stopped/disabled
  # Start It first
  #   1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
  #   2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
  ###

  print("[+] Running registry command")

  try:
    useSVCCTL = False
    if useSVCCTL:
      print("\t[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
      originalSTDOUT = sys.stdout
      sys.stdout = StringIO()
      started = startService(ip, user, pwd, domain, lmhash, nthash, aesKey, "RemoteRegistry")
      sys.stdout = originalSTDOUT
      if started:
        print("\t[+] Service RemoteRegistry started")
      else:
        print("\t[-] Failed to start RemoteRegistry Service. Exit")
        return
    else:
      print("\t[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
      # Connect to the interface WINREG
      try:
        if alternateBinding == None:
          rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
        else:
          rpctransport = transport.DCERPCTransportFactory(alternateBinding)
        if not unauthTransport:
          rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        if alternateInterface == None:
          dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
        else:
          dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))
        print("\t[+] Service already started")
      except Exception as e:
        if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
          print("\t[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
          time.sleep(2)
        else:
          print("\t[-] Got error: %s" % str(e))
          return

    # Connect to the interface WINREG
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    ACTION = cmd.split(" ")[0].upper()
    keys = extractKeys(cmd)[1:]
    if ACTION == 'QUERY':
      regQuery(dce, keys)
    elif ACTION == 'ADD':
      regAdd(dce, keys)
    elif ACTION == 'SAVE':
      regSave(dce, keys)
    elif ACTION == 'DELETE':
      regDelete(dce, keys)
    else:
      print("\t[-] Unknown registry action %s" % ACTION)
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def regSave(dce, keys):
  keyName = keys[0]
  hRootKey, subKey = stripRootKey(dce, keyName)
  outputFileName = keys[1]

  print("\t[+] Save key '%s'" % keyName)

  try:
      ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions = rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired = rrp.KEY_READ)
      rrp.hBaseRegSaveKey(dce, ans2['phkResult'], outputFileName)
      print("\t[+] Saved '%s' to '%s'" % (keyName, outputFileName))
  except Exception as e:
      print("\t[-] Couldn't save '%s': %s" % (keyName, str(e)))

def regQuery(dce, keys):
  keyName = keys[0]
  hRootKey, subKey = stripRootKey(dce, keyName)
  try:
    option = keys[1]
  except:
    option = ''
  try:
    optionKey = keys[2]
  except:
    optionKey = ''

  if (optionKey != ''):
    print("\t[+] Query entry '%s' of key '%s'" % (optionKey, keyName))
  elif (option == "/ve"):
    print("\t[+] Query default entry of key '%s'" % keyName)
  elif (option == "/s"):
    print("\t[+] Query recursively key '%s'" % keyName)
  else:
    print("\t[+] Query key '%s'" % keyName)

  res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)

  if option == "/v":
    try:
      res = rrp.hBaseRegQueryValue(dce, res['phkResult'], optionKey)
      valType = regTypes.get(res[0], 'KEY_NOT_FOUND')
      value = str(res[1])
      print(f"\t{optionKey}\t{valType}\t{value}")
    except Exception as e:
      if (str(e).find("ERROR_FILE_NOT_FOUND") >= 0):
        print("\t[-] Entry does not exist")
      else:
        print("\t[-] Unknown error: %s" % str(e))
  elif option == "/ve":
    try:
      res = rrp.hBaseRegQueryValue(dce, res['phkResult'], '')
      valType = regTypes.get(res[0], 'KEY_NOT_FOUND')
      value = str(res[1])
      print(f"\t(Default)\t{valType}\t{value}")
    except Exception as e:
      if (str(e).find("ERROR_FILE_NOT_FOUND") >= 0):
        print("\t[-] No default entry for key")
      else:
        print("\t[-] Unknown error: %s" % str(e))
  elif option == "/s":
    printAllSubkeysAndEntries(dce, subKey + '\\', res['phkResult'], 1)
  else:
    printKeyValues(dce, res['phkResult'], 1)
    i = 0
    while True:
      try:
        subKey = rrp.hBaseRegEnumKey(dce, res['phkResult'], i)['lpNameOut'][:-1]
        print(f"\t{keyName}\\{subKey}")
        i += 1
      except Exception:
        break
        # ans5 = rrp.hBaseRegGetVersion(dce, res['phkResult'])
        # ans3 = rrp.hBaseRegEnumKey(dce, res['phkResult'], 0)

def regAdd(dce, keys):
  keyName = keys[0]
  hRootKey, subKey = stripRootKey(dce, keyName)
  option = keys[1]
  if (option == "/ve"):
    entryName = ''
    entryType = keys[3]
    entryData = keys[5]
  else:
    entryName = keys[2]
    entryType = keys[4]
    entryData = keys[6]

  if (entryName != ''):
    print("\t[+] Add entry '%s' into key '%s'" % (entryName, keyName))
  else:
    print("\t[+] Add default entry into key '%s'" % keyName)

  try:
    res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") >= 0):
      print("\t[-] Access denied to open key")
    else:
      print("\t[-] Got error while opening key: '%s'" % keyName)
    return
  dwType = getattr(rrp, entryType, None)
  if dwType is None or not entryType.startswith('REG_'):
    print('\t[-] Error parsing entry type %s' % dwType)
    return

  # Fix (?) for packValue function
  if dwType in (rrp.REG_DWORD, rrp.REG_DWORD_BIG_ENDIAN, rrp.REG_DWORD_LITTLE_ENDIAN,
    rrp.REG_QWORD, rrp.REG_QWORD_LITTLE_ENDIAN):
    valueData = int(entryData)
  else:
    valueData = entryData

  res = rrp.hBaseRegSetValue(dce, res['phkResult'], entryName, dwType, valueData)
  if res['ErrorCode'] == 0:
    if (entryName != ''):
      print("\t[+] Successfully set entry '%s\\%s' of type %s to value '%s'" % (keyName, entryName, entryType, valueData))
    else:
      print("\t[+] Successfully set default entry of type %s to value '%s' for key '%s'" % (entryType, valueData, keyName))
  else:
    if (entryName != ''):
      print("\t[-] Error 0x%08x while setting entry '%s\\%s' of type %s to value '%s'" % (res['ErrorCode'], keyName, entryName, entryType, valueData))
    else:
      print("\t[-] Error 0x%08x while setting default entry of type %s to value '%s' for key '%s'" % (res['ErrorCode'], entryType, valueData, keyName))

def regDelete(dce, keys):
  keyName = keys[0]
  hRootKey, subKey = stripRootKey(dce, keyName)
  option = keys[1]
  if (option == "/v"):
    entryName = keys[2]
  else:
    entryName = ''

  if (entryName != ''):
    print("\t[+] Delete entry %s into key %s" % (entryName, keyName))
    res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
    res = rrp.hBaseRegDeleteValue(dce, res['phkResult'], entryName)
    if res['ErrorCode'] == 0:
      print("\t[+] Successfully deleted entry '%s\\%s'" % (keyName, entryName))
    else:
      print("\t[-] Error 0x%08x while deleting entry '%s\\%s'" % (res['ErrorCode'], keyName, entryName))
  else:
    if (option == "/ve"):
      print("\t[+] Delete default entry into key '%s'" % keyName)
      res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
      res = rrp.hBaseRegDeleteValue(dce, res['phkResult'], '')
      if res['ErrorCode'] == 0:
        print("\t[+] Successfully deleted default entry for key '%s'" % keyName)
      else:
        print("\t[-] Error 0x%08x while deleting default entry for key '%s'" % (res['ErrorCode'], keyName))
    elif (option == "/va"):
      print("\t[+] Delete all entries into key '%s'" % keyName)
      res1 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
      i = 0
      allSubKeys = []
      while True:
        try:
          res2 = rrp.hBaseRegEnumValue(dce, res1['phkResult'], i)
          lp_value_name = res2['lpValueNameOut'][:-1]
          allSubKeys.append(lp_value_name)
          i += 1
        except rrp.DCERPCSessionError as e:
          if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
              break

      res1 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
      for subKey in allSubKeys:
        try:
          res2 = rrp.hBaseRegDeleteValue(dce, res1['phkResult'], subKey)
          if (subKey == ''):
            subKey = "(Default)"
          if res2['ErrorCode'] == 0:
            print("\t[+] Successfully deleted entry '%s\\%s'" % (keyName, subKey))
          else:
            print("\t[-] Error 0x%08x in deletion of entry '%s\\%s'" % (res2['ErrorCode'], keyName, subKey))
        except Exception as e:
          if (subKey == ''):
            subKey = "(Default)"
          print("\t[-] Unhandled error %s in deletion of entry '%s\\%s'" % (str(e), keyName, subKey))
    else:
      print("\t[-] Unknown option: %s" % option)

def listRegSessions(ip, user, pwd, domain, lmhash, nthash, aesKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  # The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
  # BUT It can be stopped/disabled
  # Start It first
  #   1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
  #   2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
  ###

  print("[+] Listing sessions on remote host")

  try:
    useSVCCTL = False
    if useSVCCTL:
      print("\t[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
      originalSTDOUT = sys.stdout
      sys.stdout = StringIO()
      started = startService(ip, user, pwd, domain, lmhash, nthash, aesKey, "RemoteRegistry")
      sys.stdout = originalSTDOUT
      if started:
        print("\t[+] Service RemoteRegistry started")
      else:
        print("\t[-] Failed to start RemoteRegistry Service. Exit")
        return
    else:
      print("\t[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
      # Connect to the interface WINREG
      try:
        if alternateBinding == None:
          rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
        else:
          rpctransport = transport.DCERPCTransportFactory(alternateBinding)
        if not unauthTransport:
          rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        if alternateInterface == None:
          dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
        else:
          dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))
        print("\t[+] Service already started")
      except Exception as e:
        if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
          print("\t[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
          time.sleep(2)
        else:
          print("\t[-] Got error: %s" % str(e))
          return

    # Connect to the interface WINREG
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    hRootKey = rrp.hOpenUsers(dce)['phKey']
    index = 1
    SESSIONS = []
    originalSTDOUT = sys.stdout
    sys.stdout = StringIO()
    while True:
      try:
        res = rrp.hBaseRegEnumKey(dce, hRootKey, index)
        SIDString = res['lpNameOut'].rstrip('\0')
        if SIDString.startswith("S-") and not SIDString.endswith("Classes"):
          SESSIONS.append(SIDToName(ip, user, pwd, domain, lmhash, nthash, aesKey, SIDString))
        index += 1
      except:
          break
    sys.stdout = originalSTDOUT
    for session in SESSIONS:
      print(f"\t{session}")
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def printAllSubkeysAndEntriesSD(dce, keyName, keyHandler, nbTab):
  index = 0
  while True:
    try:
      subkey = rrp.hBaseRegEnumKey(dce, keyHandler, index)
      index += 1
      res = rrp.hBaseRegOpenKey(dce, keyHandler, subkey['lpNameOut'], samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
      newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
      sys.stdout.write('\t' * nbTab + newKeyName + " ")
      sdBytes = b"".join(rrp.hBaseRegGetKeySecurity(dce, keyHandler, 0x4)['pRpcSecurityDescriptorOut']['lpSecurityDescriptor']) # 0x4 = DACL_SECURITY_INFORMATION
      print(base64.b64encode(sdBytes).decode())
      printAllSubkeysAndEntriesSD(dce, newKeyName, res['phkResult'], nbTab + 1)
    except Exception as e:
      if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
        break
      elif str(e).find('access_denied') >= 0:
        print('\t' * nbTab + "[-] Cannot access subkey '%s', bypassing it" % subkey['lpNameOut'][:-1])
        continue
      elif str(e).find('rpc_x_bad_stub_data') >= 0:
        print('\t' * nbTab + "[-] Fault call, cannot retrieve value for '%s', bypassing it" % subkey['lpNameOut'][:-1])
        return
      else:
        raise e

def listRegSD(ip, user, pwd, domain, lmhash, nthash, aesKey, rootKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  # The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
  # BUT It can be stopped/disabled
  # Start It first
  #   1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
  #   2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
  ###

  print("[+] Displaying Security Descriptor of registry")

  try:
    useSVCCTL = False
    if useSVCCTL:
      print("\t[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
      originalSTDOUT = sys.stdout
      sys.stdout = StringIO()
      started = startService(ip, user, pwd, domain, lmhash, nthash, aesKey, "RemoteRegistry")
      sys.stdout = originalSTDOUT
      if started:
        print("\t[+] Service RemoteRegistry started")
      else:
        print("\t[-] Failed to start RemoteRegistry Service. Exit")
        return
    else:
      print("\t[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
      # Connect to the interface WINREG
      try:
        if alternateBinding == None:
          rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
        else:
          rpctransport = transport.DCERPCTransportFactory(alternateBinding)
        if not unauthTransport:
          rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        if alternateInterface == None:
          dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
        else:
          dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))
        print("\t[+] Service already started")
      except Exception as e:
        if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
          print("\t[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
          time.sleep(2)
        else:
          print("\t[-] Got error: %s" % str(e))
          return

    # Connect to the interface WINREG
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    if rootKey.upper() == 'HKLM':
      ans = rrp.hOpenLocalMachine(dce)
    elif rootKey.upper() == 'HKCU':
      ans = rrp.hOpenCurrentUser(dce)
    elif rootKey.upper() == 'HKCR':
      ans = rrp.hOpenClassesRoot(dce)
    elif rootKey.upper() == 'HKU':
      ans = rrp.hOpenUsers(dce)
    elif rootKey.upper() == 'HKCC':
      ans = rrp.hOpenCurrentConfig(dce)
    hRootKey = ans['phKey']
    printAllSubkeysAndEntriesSD(dce, rootKey + "\\", hRootKey, 1)
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

##################################################################################
### [MS-LSAT] = Local Security Authority (Translation Methods) Remote Protocol ###
###    [MS-LSAD] = Local Security Authority (Domain Policy) Remote Protocol    ###
###                            Interface = LSARPC                              ###
##################################################################################

from impacket.dcerpc.v5 import lsat, lsad

def SIDToName(ip, user, pwd, domain, lmhash, nthash, aesKey, SIDString, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  ###

  print("[+] Lookup name of SID")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    policyHandle = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | lsad.MAXIMUM_ALLOWED)['PolicyHandle']
    try:
      res = lsat.hLsarLookupSids(dce, policyHandle, [SIDString], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
    except Exception as e:
      if str(e).find('STATUS_NONE_MAPPED') >= 0:
        print('\t[-] SID %s lookup failed, return status: STATUS_NONE_MAPPED' % SIDString)
        return
      else:
        raise e
    domains = []
    for entry in res['ReferencedDomains']['Domains']:
      domains.append(entry['Name'])
    for entry in res['TranslatedNames']['Names']:
        domain = domains[entry['DomainIndex']]
        name = entry['Name']
        login = "%s\\%s" % (domain, name)
        print(f"\t{SIDString} = {login}")

    return login
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def NameToSID(ip, user, pwd, domain, lmhash, nthash, aesKey, name, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Does not require administrative rights
  ###

  print("[+] Lookup SID of name")

  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    policyHandle = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | lsad.MAXIMUM_ALLOWED)['PolicyHandle']
    try:
      res = lsat.hLsarLookupNames(dce, policyHandle, [name], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
    except Exception as e:
      if str(e).find('STATUS_NONE_MAPPED') >= 0:
        print('[-] Name not found')
        return
      else:
        raise e
    domainSIDs = []
    for entry in res['ReferencedDomains']['Domains']:
      domainSIDs.append(entry['Sid'].formatCanonical())
    for entry in res['TranslatedSids']['Sids']:
      domainSID = domainSIDs[entry['DomainIndex']]
      SIDString = f"{domainSID}-{entry['RelativeId']}"
      print(f"\t{name} = {SIDString}")

    return SIDString
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def NameToSID2(ip, user, pwd, domain, lmhash, nthash, aesKey, name, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))
    
    # Query methods of the interface
    policyHandle = lsad.hLsarOpenPolicy2(dce)['PolicyHandle']
    try:
      res = lsat.hLsarLookupNames3(dce, policyHandle, [name], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
    except Exception as e:
      if str(e).find('STATUS_NONE_MAPPED') >= 0:
        print('[-] Name not found')
        return
      else:
        raise e
    return res['TranslatedSids']['Sids'][0]['Sid']
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

#####################################################################################
### [MS-SAMR] = Security Account Manager (SAM) Remote Protocol (Client-to-Server) ###
###                               Interface = SAMR                                ###
#####################################################################################

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.dtypes import RPC_SID

def extractKeys(cmd):
  # Regular expression to match words within single quotes and words without quotes
  pattern = r"'[^']*'|\S+"
  # Find all matches using the pattern
  words = re.findall(pattern, cmd)
  # Remove single quotes from extracted words
  words = [word.strip("'") for word in words]

  return words

def openAlias(dce, domainHandle, aliasName):
  aliasRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [aliasName])['RelativeIds']['Element'][0]['Data']
  aliasHandle = samr.hSamrOpenAlias(dce, domainHandle, aliasId = aliasRID)['AliasHandle']
  return aliasHandle

def openGroup(dce, domainHandle, groupName):
  groupRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])['RelativeIds']['Element'][0]['Data']
  groupHandle = samr.hSamrOpenGroup(dce, domainHandle, groupId = groupRID)['GroupHandle']
  return groupHandle

def openUser(dce, domainHandle, userName):
  userRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [userName])['RelativeIds']['Element'][0]['Data']
  userHandle = samr.hSamrOpenUser(dce, domainHandle, userId = userRID)['UserHandle']
  return userHandle

def openDomain(dce, Builtin = False):
  index = 1 if Builtin else 0
  serverHandle = samr.hSamrConnect(dce)['ServerHandle']
  domainName = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)['Buffer']['Buffer'][index]['Name']
  domainRID = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)['DomainId']
  domainHandle = samr.hSamrOpenDomain(dce, serverHandle, domainId = domainRID)['DomainHandle']
  return domainHandle

def getUnixTime(t):
  t -= 116444736000000000
  t /= 10000000
  return t

def getTimeString(large_integer):
  time = (large_integer['HighPart'] << 32) + large_integer['LowPart']
  if time == 0 or time == 0x7FFFFFFFFFFFFFFF:
      time = 'Never'
  else:
      time = datetime.datetime.fromtimestamp(getUnixTime(time))
      time = time.strftime("%m/%d/%Y %H:%M:%S %p")
  return time
    
def formatLogonHours(s):
  logon_hours = ''.join(map(lambda b: b.hex(), s))
  if logon_hours == ('f' * 42):
      logon_hours = "All"
  return logon_hours

def b2s(b):
  return "Yes" if b else "No"

def displayAccount(account):
  print("\tUser name".ljust(30), account['UserName'])
  print("\tFull name".ljust(30), account['FullName'])
  print("\tComment".ljust(30), account['AdminComment'])
  print("\tUser's comment".ljust(30), account['UserComment'])
  print("\tCountry/region code".ljust(30), "000 (System Default)" if account['CountryCode'] == 0 else account['CountryCode'])
  print("\tAccount active".ljust(30), b2s(account['WhichFields'] & samr.USER_ACCOUNT_DISABLED == samr.USER_ACCOUNT_DISABLED))
  print("\tAccount expires".ljust(30), getTimeString(account['AccountExpires']))
  print('')
  print("\tPassword last set".ljust(30), getTimeString(account['PasswordLastSet']))
  print("\tPassword expires".ljust(30), getTimeString(account['PasswordMustChange']))
  print("\tPassword changeable".ljust(30), getTimeString(account['PasswordCanChange']))
  print("\tPassword required".ljust(30), b2s(account['WhichFields'] & samr.USER_PASSWORD_NOT_REQUIRED == samr.USER_PASSWORD_NOT_REQUIRED))
  print("\tUser may change password".ljust(30), b2s(account['WhichFields'] & samr.UF_PASSWD_CANT_CHANGE == samr.UF_PASSWD_CANT_CHANGE))
  print('')
  print("\tWorkstations allowed".ljust(30), "All" if not account['WorkStations'] else account['WorkStations'])
  print("\tLogon script".ljust(30), account['ScriptPath'])
  print("\tUser profile".ljust(30), account['ProfilePath'])
  print("\tHome directory".ljust(30), account['HomeDirectory'])
  print("\tLast logon".ljust(30), getTimeString(account['LastLogon']))
  print("\tLogon count".ljust(30), account['LogonCount'])
  print('')
  print("\tLogon hours allowed".ljust(30), formatLogonHours(account['LogonHours']['LogonHours']))
  print('')
  print("\tLocal Group Memberships")
  for group in account['LocalGroups']:
      print("\t\t* {}".format(group))
  print('')
  print("\tGlobal Group memberships")
  for group in account['GlobalGroups']:
      print("\t\t* {}".format(group))

def netCMD(ip, user, pwd, domain, lmhash, nthash, aesKey, netCMD, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
  ###
  # Require administrative rights for Windows 10, version 1607 (or later) non-domain controller
  # Does not require administrative rights for others
  # https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
  ###
  
  try:
    # Connect to the interface
    if alternateBinding == None:
      rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\samr]' % ip)
    else:
      rpctransport = transport.DCERPCTransportFactory(alternateBinding)
    if not unauthTransport:
      rpctransport.set_credentials(user, pwd, domain, lmhash, nthash, aesKey)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    if alternateInterface == None:
      dce.bind(uuid.uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0')))
    else:
      dce.bind(uuid.uuidtup_to_bin(tuple(alternateInterface.split(":"))))

    # Query methods of the interface
    keys = extractKeys(netCMD)
    ACTION = keys[0]
    if ACTION == "user":
      queryAccounts(dce, ip, "User", keys[1:])
    elif ACTION == "computer":
      queryAccounts(dce, ip, "Computer", keys[1:])
    elif ACTION == "group":
      queryGroups(dce, ip, user, pwd, domain, lmhash, nthash, aesKey, "Group", keys[1:])
    elif ACTION == "localgroup":
      queryGroups(dce, ip, user, pwd, domain, lmhash, nthash, aesKey, "Aliases", keys[1:])
    else:
      print("[-] Unknown NET action '%s'" % ACTION)
  except Exception as e:
    if (str(e).find("rpc_s_access_denied") != -1):
      print(f"\t[-] Access denied")
    else:
      print(f"\t[-] Got error: {str(e)}")

def queryAccounts(dce, ip, accountType, keys):
  lenKeys = len(keys)
  if (lenKeys == 0):
    # Enumerate all accounts
    print(f"[+] {accountType} accounts for \\\\{ip}")
    domainHandle = openDomain(dce)
    if accountType == "User":
      res = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_NORMAL_ACCOUNT)
    else:
      res = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT)
    for entry in res['Buffer']['Buffer']:
      print(f"\t{entry['Name']} - {entry['RelativeId']}")
  else:
    if (lenKeys == 1):
      # Display an account
      accountName = keys[0]
      print(f"[+] {accountType} account '{accountName}' for \\\\{ip}")
      domainHandle = openDomain(dce)
      accountHandle = openUser(dce, domainHandle, accountName)
      res = samr.hSamrQueryInformationUser2(dce, accountHandle, samr.USER_INFORMATION_CLASS.UserAllInformation)
      account = res['Buffer']['All']
      sidArray = samr.SAMPR_PSID_ARRAY()
      groups = samr.hSamrGetGroupsForUser(dce, accountHandle)['Groups']['Groups']
      groupRIDs = list(map(lambda g: g['RelativeId'], groups))
      for group in groups:
        groupRID = group['RelativeId']
        groupHandle = samr.hSamrOpenGroup(dce, domainHandle, groupId = groupRID)['GroupHandle']
        groupSID = samr.hSamrRidToSid(dce, groupHandle, groupRID)['Sid']
        si = samr.PSAMPR_SID_INFORMATION()
        si['SidPointer'] = groupSID
        sidArray['Sids'].append(si)
      globalGroups = samr.hSamrLookupIdsInDomain(dce, domainHandle, groupRIDs)
      account.fields['GlobalGroups'] = list(map(lambda a: a['Data'], globalGroups['Names']['Element']))
      domainHandle = openDomain(dce, True)
      aliasMembership = samr.hSamrGetAliasMembership(dce, domainHandle, sidArray)
      aliasIDs = list(map(lambda a: a['Data'], aliasMembership['Membership']['Element']))
      localGroups = samr.hSamrLookupIdsInDomain(dce, domainHandle, aliasIDs)
      account.fields['LocalGroups'] = list(map(lambda a: a['Data'], localGroups['Names']['Element']))
      displayAccount(account)
    else:
      if (lenKeys == 2):
        # Delete an account
        accountName = keys[0]
        print(f"[+] Deleting {accountType.lower()} account '{accountName}'")
        domainHandle = openDomain(dce)
        accountHandle = openUser(dce, domainHandle, accountName)
        samr.hSamrDeleteUser(dce, accountHandle)
        print("\t[+] Account successfully deleted")
      else:
        if (lenKeys == 3):
          # Create an account
          accountName = keys[0]
          print(f"[+] Creating {accountType.lower()} account '{accountName}'")
          domainHandle = openDomain(dce)
          b64Pwd, NT = keys[1].split(":")
          # New created account will be disabled in most cases
          # And the account will have the USER_FORCE_PASSWORD_CHANGE flag
          # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a98d7fbb-1735-4fbf-b41a-ef363c899002
          # Thus, after created the account, set the userAccountControl attribute with SamrSetInformationUser2()
          if accountType == "User":
            samr.hSamrCreateUser2InDomain(dce, domainHandle, accountName, samr.USER_NORMAL_ACCOUNT)
          else:
            samr.hSamrCreateUser2InDomain(dce, domainHandle, accountName, samr.USER_WORKSTATION_TRUST_ACCOUNT)
          try:
            buffer = samr.SAMPR_USER_INFO_BUFFER()
            buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
            if accountType == "User":
              buffer['Control']['UserAccountControl'] = samr.USER_NORMAL_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
            else:
              buffer['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
            accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
            accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
            samr.hSamrSetNTInternal1(dce, accountHandle, base64.b64decode(b64Pwd).decode(), NT)
            samr.hSamrSetInformationUser2(dce, accountHandle, buffer)
            print("\t[+] Account sucessfully created")
          except Exception as e:
            if (str(e).find("rpc_s_access_denied") != -1):
              print(f"\t[-] Access denied")
            else:
              print(f"\t[-] Got error: {str(e)}")
            try:
              accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
              accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
              samr.hSamrDeleteUser(dce, accountHandle)
            except:
              pass
        else:
          if (lenKeys > 5):
            print("\t[-] Invalid cmd: net %s" % (" ".join(keys)))
          else:
            # Set user password
            accountName = keys[0]
            print(f"[+] Editing {accountType.lower()} account '{accountName}' password")
            domainHandle = openDomain(dce)
            accountHandle = openUser(dce, domainHandle, accountName)
            b64CurrentPwd, b64NewPwd = keys[1].split(":")
            currentLM, newLM = keys[2].split(":")
            currentNT, newNT = keys[3].split(":")
            if (lenKeys == 5):
              injectSAM = True
            else:
              injectSAM = False
            if b64NewPwd != '':
              if b64CurrentPwd == '' and currentNT == '':
                print(f"\t[-] Current {accountType.lower()} pwd or NT hash required")
              else:
                samr.hSamrUnicodeChangePasswordUser2(dce, "\x00", accountName, base64.b64decode(b64CurrentPwd).decode(), base64.b64decode(b64NewPwd).decode(), '', currentNT)
            elif newNT != '':
              if injectSAM: # Require administrative rights. Allow to bypass password history policy
                samr.hSamrSetNTInternal1(dce, accountHandle, '', newNT)
              else:
                if (newLM != '') and (b64CurrentPwd != '' or currentNT != ''):
                  samr.hSamrChangePasswordUser(dce, accountHandle, base64.b64decode(b64CurrentPwd).decode(), '', currentNT, newLM, newNT) # User will have to change his pwd at next logon
                else:
                  print(f"\t[-] New {accountType.lower()} LM hash AND current {accountType.lower()} pwd or NT hash required")
            else:
              print(f"\t[-] New {accountType.lower()} pwd or NT hash required")
            print("\t[+] Account password successfully edited")

def queryGroups(dce, ip, user, pwd, domain, lmhash, nthash, aesKey, groupType, keys):
  lenKeys = len(keys)
  if (lenKeys == 0):
    # Enumerate all groups
    print(f"[+] {groupType} accounts for \\\\{ip}")
    if groupType == "Group":
      domainHandle = openDomain(dce)
      res = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
    else:
      domainHandle = openDomain(dce, True)
      res = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
    for entry in res['Buffer']['Buffer']:
      print(f"\t{entry['Name']} - {entry['RelativeId']}")
  else:
    if (lenKeys == 1):
      # Query a group
      groupName = keys[0]
      print(f"[+] Listing members of {groupType.lower()} '{groupName}'")
      if groupType == "Group":
        domainHandle = openDomain(dce)
        groupHandle = openGroup(dce, domainHandle, groupName)
        res = samr.hSamrQueryInformationGroup(dce, groupHandle, samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)['Buffer']['General']
        groupComment = res['AdminComment']
        print("\tGroup name".ljust(30), groupName)
        print("\tComment".ljust(30), groupComment)
        print("\tMembers")
        membersRIDs = samr.hSamrGetMembersInGroup(dce, groupHandle)
        membersNames = samr.hSamrLookupIdsInDomain(dce, domainHandle, list(map(lambda a: a['Data'], membersRIDs['Members']['Members'])))
        for entry in membersNames['Names']['Element']:
          memberName = entry['Data']
          print("\t".ljust(30), memberName)
      else:
        domainHandle = openDomain(dce, True)
        aliasName = keys[0]
        aliasHandle = openAlias(dce, domainHandle, aliasName)
        res = samr.hSamrQueryInformationAlias(dce, aliasHandle, samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation)['Buffer']['General']
        aliasComment = res['AdminComment']
        print("\tAlias name".ljust(30), aliasName)
        print("\tComment".ljust(30), aliasComment)
        print("\tMembers")
        res = samr.hSamrGetMembersInAlias(dce, aliasHandle)
        for member in res['Members']['Sids']:
          SIDString = member['SidPointer'].formatCanonical()
          originalSTDOUT = sys.stdout
          sys.stdout = StringIO()
          memberName = SIDToName(ip, user, pwd, domain, lmhash, nthash, aesKey, SIDString) # Use LSARPC interface to resolve SIDs
          sys.stdout = originalSTDOUT
          print("\t".ljust(30), memberName)
    else:
      if (lenKeys == 2):
        if keys[1] == "/add":
          # Create a group
          groupName = keys[0]
          print(f"[+] Creating {groupType.lower()} '{groupName}'")
          if groupType == "Group":
            domainHandle = openDomain(dce)
            samr.hSamrCreateGroupInDomain(dce, domainHandle, groupName)
          else:
            domainHandle = openDomain(dce, True)
            aliasName = keys[0]
            samr.hSamrCreateAliasInDomain(dce, domainHandle, aliasName)
          print(f"\t[+] {groupType} successfully created")
        elif keys[1] == "/del":
          # Delete a group
          groupName = keys[0]
          print(f"[+] Deleting {groupType.lower()} '{groupName}'")
          if groupType == "Group":
            domainHandle = openDomain(dce)
            groupHandle = openGroup(dce, domainHandle, groupName)
            samr.hSamrDeleteGroup(dce, groupHandle)
          else:
            domainHandle = openDomain(dce, True)
            aliasName = keys[0]
            aliasHandle = openAlias(dce, domainHandle, aliasName)
            samr.hSamrDeleteAlias(dce, aliasHandle)
          print(f"\t[+] {groupType} successfully deleted")
        else:
          print("\t[-] Invalid cmd: net %s" % (" ".join(keys)))
      else:
        if (lenKeys == 3):
          if keys[2] == "/add":
            # Add account to group
            groupName = keys[0]
            accountName = keys[1]
            print(f"[+] Adding account '{accountName}' to '{groupName}'")
            if groupType == "Group":
              domainHandle = openDomain(dce)
              groupHandle = openGroup(dce, domainHandle, groupName)
              accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
              samr.hSamrAddMemberToGroup(dce, groupHandle, accountRID, samr.SE_GROUP_ENABLED_BY_DEFAULT)
            else:
              domainHandle = openDomain(dce, True)
              aliasName = keys[0]
              aliasHandle = openAlias(dce, domainHandle, aliasName)
              originalSTDOUT = sys.stdout
              sys.stdout = StringIO()
              accountSID = NameToSID2(ip, user, pwd, domain, lmhash, nthash, aesKey, accountName) # Use LSARPC interface to resolve name
              sys.stdout = originalSTDOUT
              samr.hSamrAddMemberToAlias(dce, aliasHandle, accountSID)
            print("\t[+] Account successfully added")
          elif keys[2] == "/del":
            # Remove account from group
            groupName = keys[0]
            accountName = keys[1]
            print(f"[+] Removing account '{accountName}' from '{groupName}'")
            if groupType == "Group":
              domainHandle = openDomain(dce)
              groupHandle = openGroup(dce, domainHandle, groupName)
              accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
              samr.hSamrRemoveMemberFromGroup(dce, groupHandle, accountRID)
            else:
              domainHandle = openDomain(dce, True)
              aliasName = keys[0]
              aliasHandle = openAlias(dce, domainHandle, aliasName)
              originalSTDOUT = sys.stdout
              sys.stdout = StringIO()
              accountSID = NameToSID2(ip, user, pwd, domain, lmhash, nthash, aesKey, accountName) # Use LSARPC interface to resolve name
              sys.stdout = originalSTDOUT
              samr.hSamrRemoveMemberFromAlias(dce, aliasHandle, accountSID)
            print("\t[+] Account successfully removed")
          else:
            print("\t[-] Invalid cmd: net %s" % (" ".join(keys)))
        else:
          print("\t[-] Invalid cmd: net %s" % (" ".join(keys)))

############
### MAIN ###
############

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description = "RPC Util: Discover many procedures through RPC interfaces", formatter_class = argparse.RawTextHelpFormatter)

  auth_group = parser.add_argument_group('Authentication options')
  auth_group.add_argument("--ip", help = "Target IP", required = True)
  auth_group.add_argument("--username", help = "Username for authentication")
  auth_group.add_argument("--password", help = "Password for authentication")
  auth_group.add_argument("--domain", help = "Domain for authentication (Hostname for local authentication)")
  auth_group.add_argument("--lmHash", help = "LM Hash for NTLM authentication", default = "")
  auth_group.add_argument("--ntHash", help = "NT Hash for NTLM authentication", default = "")
  auth_group.add_argument("--aesKey", help = "AES 128/256 key for Kerberos authentication", default = "")
  auth_group.add_argument("--alternateBinding", help = "Alternate String Binding to access RPC interface")
  auth_group.add_argument("--alternateInterface", help = "Alternate RPC interface in the form of <UUID>:<Version>")
  auth_group.add_argument("--unauthTransport", help = "Do not authenticate through transport protocol", action = "store_true")
  auth_group.add_argument("--unauthBinding", help = "Do not authenticate through binding", action = "store_true")

  msrpce_group = parser.add_argument_group('[MS-RPCE]-C706 Remote Procedure Call Protocol Extensions options')
  msrpce_group.add_argument("--listEndpoints", help = "List exposed RPC endpoints through EPMAPPER interface", action = "store_true")
  msrpce_group.add_argument("--searchUnauthBindings", help = "Search unauthenticated bindings through exposed RPC endpoints", action = "store_true")
  msrpce_group.add_argument("--getOSArch", help = "Get target Windows OS architecture (x86/x64)", action = "store_true")

  msscmr_group = parser.add_argument_group('[MS-SCMR] Service Control Manager Remote Protocol options')
  msscmr_group.add_argument("--cmdSVCCTL", help = "System command to execute through SVCCTL interface")
  msscmr_group.add_argument("--startService", help = "Service to start through SVCCTL interface")
  msscmr_group.add_argument("--listServices", help = "List running services and by which users through SVCCTL interface", action = "store_true")

  mstsch_group = parser.add_argument_group('[MS-TSCH] Task Scheduler Service Remoting Protocol options')
  mstsch_group.add_argument("--cmdITaskSchedulerService", help = "System command to execute through ITaskSchedulerService interface")
  mstsch_group.add_argument("--listScheduledTasks", help = "List Scheduled Tasks and by which users through ITaskSchedulerService interface", action = "store_true")
  mstsch_group.add_argument("--cmdATSVC", help = "System command to execute through ATSVC interface [NOT WORKING]")

  msdcom_group = parser.add_argument_group('[MS-DCOM] Distributed Component Object Model (DCOM) Remote Protocol options')
  msdcom_group.add_argument("--cmdDCOM1", help = "System command to execute through ShellWindows/ShellBrowserWindow/MMC20 COM objects")
  msdcom_group.add_argument("--cmdDCOM2", help = "System command to execute through WbemLevel1Login COM object")

  mststs_group = parser.add_argument_group('[MS-TSTS] Terminal Services Terminal Server Runtime Interface Protocol options')
  mststs_group.add_argument("--listRDSSessions", help = "List Remote Desktop Services sessions through TermSrvEnumeration/TermSrvSession interfaces", action = "store_true")
  mststs_group.add_argument("--listProcesses", help = "List running processes through LegacyAPI interface", action = "store_true")

  mssrvs_group = parser.add_argument_group('[MS-SRVS] Server Service Remote Protocol options')
  mssrvs_group.add_argument("--listSessions", help = "List remote sessions through SRVSVC interface", action = "store_true")

  mswkst_group = parser.add_argument_group('[MS-WKST] Workstation Service Remote Protocol options')
  mswkst_group.add_argument("--listLoggedIn", help = "List logged in users through WKSSVC interface", action = "store_true")

  msrrp_group = parser.add_argument_group('[MS-RRP] Windows Remote Registry Protocol options')
  msrrp_group.add_argument("--regCMD", help = '''Registry cmd through WINREG interface in the form of:
      query '<KeyName>' [/v '<EntryName>'|/ve|/s]
      add '<KeyName>' /v '<EntryName>'|/ve /t <EntryType> /d '<EntryData>'
      delete '<KeyName>' /v '<EntryName>'|/ve|/va
      save '<KeyName>' '<RemoteOutputPath>\'''')
  msrrp_group.add_argument("--listRegSessions", help = "List remote sessions through WINREG interface by querying HKU\<SID>", action = "store_true")
  msrrp_group.add_argument("--listRegSD", help = "List remote registries Security Descriptor through WINREG interface", choices = ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"])

  mslsatlsad_group = parser.add_argument_group('[MS-LSAT]/[MS-LSAD] Local Security Authority (Translation Methods/Domain Policy) Remote Protocol options')
  mslsatlsad_group.add_argument("--SIDToName", help = "Lookup name of provided SID through LSARPC interface")
  mslsatlsad_group.add_argument("--NameToSID", help = "Lookup SID of provided SAM Account Name through LSARPC interface")

  mssamr_group = parser.add_argument_group('[MS-SAMR] Security Account Manager (SAM) Remote Protocol (Client-to-Server) options')
  mssamr_group.add_argument("--netCMD", help = '''Net cmd through SAMR interface in the form of:
      user
      user '<UserName>'
      user '<UserName>' /del
      user '<UserName>' [<B64Pwd>]:[<NT>] /add
      user '<UserName>' [<B64CurrentPwd>]:[<B64NewPwd>] [<CurrentLM>:<NewLM>] [<CurrentNT>:<NewNT>] [/injectSAM]
      computer
      computer '<ComputerName>'
      computer '<ComputerName>' /del
      computer '<ComputerName>' [<B64Pwd>]:[<NT>] /add
      computer '<ComputerName>' [<B64CurrentPwd>]:[<B64NewPwd>] [<CurrentLM>:<NewLM>] [<CurrentNT>:<NewNT>] [/injectSAM]
      group
      group '<GroupName>'
      group '<GroupName>' /del
      group '<GroupName>' /add
      group '<GroupName>' '<UserName>' /add
      group '<GroupName>' '<UserName>' /del
      localgroup
      localgroup '<GroupName>'
      localgroup '<GroupName>' /del
      localgroup '<GroupName>' /add
      localgroup '<GroupName>' '<UserName>' /add
      localgroup '<GroupName>' '<UserName>' /del''')
  
  args = parser.parse_args()

  if (args.listEndpoints):
    endpoints = listEndpoints(args.ip)
  if (args.searchUnauthBindings):
    searchUnauthBindings(args.ip)
  if (args.getOSArch):
    getOSArch(args.ip)
  if (args.cmdSVCCTL != None):
    RCESVCCTL(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.cmdSVCCTL, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.startService != None):
    startService(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.startService, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listServices):
    listServices(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.cmdITaskSchedulerService != None):
    RCEITaskSchedulerService(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.cmdITaskSchedulerService, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listScheduledTasks):
    listScheduledTasks(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.cmdATSVC != None):
    RCEATSVC(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.cmdATSVC, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.cmdDCOM1 != None):
    RCEDCOM1(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.cmdDCOM1, args.unauthTransport, args.unauthBinding)
  if (args.cmdDCOM2 != None):
    RCEDCOM2(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.cmdDCOM2, args.unauthTransport, args.unauthBinding)
  if (args.listRDSSessions):
    listRDSSessions(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding)
  if (args.listProcesses):
    listProcesses(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listSessions):
    listSessions(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listLoggedIn):
    listLoggedIn(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.regCMD != None):
    regCMD(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.regCMD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listRegSessions):
    listRegSessions(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.listRegSD):
    listRegSD(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.listRegSD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.SIDToName != None):
    name = SIDToName(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.SIDToName, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.NameToSID != None):
    sid = NameToSID(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.NameToSID, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
  if (args.netCMD != None):
    netCMD(args.ip, args.username, args.password, args.domain, args.lmHash, args.ntHash, args.aesKey, args.netCMD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)