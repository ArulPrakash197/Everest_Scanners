######################################################################
###############do not change these following lines####################
from unmsutil import *
from scanner import LearnedResource, BaseScanner, logScanMsg, logScanExceptionMsg
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.smi import builder, view
######################################################################
######################################################################

from uwebcom import *

def getEnterpriseID() :
	return "Cisco Enterprise MIB", "enterprises.9"

def getScanner() :
	return "Cisco Enterprise MIB", "enterprises.9", CiscoScannerAPI()

def loadMIB(mibName='CISCO-PRODUCTS-MIB'):
	cmdGen = cmdgen.CommandGenerator()
	mibBuilder = cmdGen.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
	mibPath = mibBuilder.getMibSources() + (builder.DirMibSource(os.getcwd() + '/mibs'),)
	mibBuilder.setMibSources(*mibPath)
	mibBuilder.loadModules(mibName)
	mibViewController = view.MibViewController(mibBuilder)
	return mibViewController

class CiscoScannerAPI(BaseScanner):

	def __init__(self):
		BaseScanner.__init__(self)
		self.device_profile = 'CiscoDevice.cfg'

	def getDeviceVendor(self):
		return 'Cisco'

	def getDeviceModel(self):
		try:
			productType = self.system_values.get('sysobjectid', '')
			if productType.startswith('enterprises.'):
				productType = productType.replace('enterprises.', '1.3.6.1.4.1.')
			mibViewController = loadMIB()
			oid, label, suffix = mibViewController.getNodeName(tuple(map(lambda z: int(z), productType.split('.'))))
			device_model = label[-1]
			if device_model.startswith('Cisco'):
				return device_model[len('Cisco'):]
			if device_model:
				return device_model
		except Exception, msg:
			logExceptionMsg(4, 'Exception in Cisco Scanner getDeviceModel - %s' %msg, self.module_name)
		except:
			logExceptionMsg(4, 'Exception in Cisco Scanner getDeviceModel', self.module_name)
		return None

	def getDeviceType(self):
		#TODO: find device type from MIB
		return 'Router'

	def getOSName(self):
		return 'IOS'

	def getOSVersion(self):
		try:
			actual_descr = self.system_values.get('description', '')
			os_ver = re.search(r'Version\s+(.*),\s+RELEASE', actual_descr).groups()
			os_version = string.join(os_ver, ' ').strip()
		except:
			os_version = ''
		return os_version

	def getEnvironmentMonitoring(self):
		params = {}
		try:
			try:
				self.logMsg('Checking for Environment MIB to get Voltage')
				#Check For Environment MIB to get Voltage
				ins = self.multiSNMPGet("get", [".1.3.6.1.4.1.9.9.13.1.2.1.3.1"])
				if ins:
					params["environment"] = 1
			except Exception, msg:
				logScanExceptionMsg(4, 'Exception in getting Environment MIB - %s' %msg, self.module_name)
			# Check for CPU
			try:
				self.logMsg('Checking for CPU from Cisco Local MIBs')
				cpus = self.getSNMPTable(['.1.3.6.1.4.1.9.9.109.1.1.1.1.8'])
				if cpus:
					for cpu in cpus:
						cpu_oid = chopRight(cpu[0].oid, '.')
						params['cpu'] = 1
						params['cpuoid'] = "8.%s" %cpu_oid
						break
				else:
					#For Backward Compact
					self.logMsg('Checking for CPU from Cisco Local MIBs for Older Versions')
					cpus = self.getSNMPTable(['.1.3.6.1.4.1.9.9.109.1.1.1.1.4'])
					if cpus:
						for cpu in cpus:
							cpu_oid = chopRight(cpu[0].oid, '.')
							params['cpu'] = 1
							params['cpuoid'] = "4.%s" %cpu_oid
							break
			except Exception, msg:
				logScanExceptionMsg(4, 'Exception in Cisco Scanner API getting CPU Information - %s' %msg, self.module_name)
			# Get Memory Information in bytes
			try:
				self.logMsg('Checking for Memory Pool Size')
				memory_size = ''
				ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.9.9.48.1.1.1.5.1', '1.3.6.1.4.1.9.9.48.1.1.1.6.1'])
				if ins:
					try :
						params['memory'] = 1
						memory_used = self.verifySNMPResponse(ins[0].value)
						self.logMsg('memory used-%s'%memory_used)
						memory_free =self.verifySNMPResponse( ins[1].value)
						print '\n \n memory_used,memory_free ....',memory_used,memory_free
						self.logMsg('memory free-%s'%memory_free)
						if not memory_used and not memory_free :
							raise Exception('Check for the other cisco model .....')
						memory_size = safe_long(memory_used) + safe_long(memory_free)
						self.logMsg('Obtained Memory Pool Size - %s' %memory_size)
						self.logMsg('Going to scan Nexus memory')
					except :
						ins = self.getSNMPTable( ['.1.3.6.1.4.1.9.9.109.1.1.1.1.12'])
						if ins:
							self.logMsg('Scanning Nexus meomory : %s '%(ins))
							params['memory'] = 0
							mem_oid= chopRight(ins[0][0].oid,'1.3.6.1.4.1.9.9.109.1.1.1.1.12.')
							params['memoryoid']=mem_oid
							params['nexus_mem'] = 1
							memory_used = ins[0].value
							memory_free = ins[1].value
							memory_size = safe_long(memory_used) + safe_long(memory_free)
							self.logMsg('Obtained Nexus Memory Pool Size - %s' %memory_size)

			except Exception as msg :
				logScanExceptionMsg(4, 'Exception in Cisco Scanner API getting Memory Size Information - %s' %msg, self.module_name)
				memory_size = ''
			if memory_size:
				params['memory_size'] = memory_size
			self.logMsg('Environment MIB scanning completed')
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in Cisco Scanner API - getEnvironmentMonitoring - %s' %msg, self.module_name)
		return params

	def getVLANDetails(self) :
		ret = {}	#dictionary with key as the oidIndex and value the list of vlanids
		try :
			self.logMsg('Scanning Cisco VLAN Details')
			vlantable = self.getSNMPTable([".1.3.6.1.4.1.9.9.68.1.2.2.1.1", ".1.3.6.1.4.1.9.9.68.1.2.2.1.2",
							  ".1.3.6.1.4.1.9.9.68.1.2.2.1.4"])
			vlantable = map(lambda a : (string.split(a[0].oid, ".")[-1], a[0].value, a[1].value, a[2].value), vlantable)
			for oid, vlantype, vmvlan, vmvlans in vlantable : 
				if safe_int(vlantype) == 1 :
					#static vlan membership for the port
					ret[oid] = [vmvlan]
				elif safe_int(vlantype) == 2 :
					#dynamic vlan membership for the port
					ret[oid] = [vmvlan]
				elif safe_int(vlantype) == 3 :
					#multi vlan membership for the port
					ret[oid] = []
					j = 0
					for i in range(len(vmvlans)):
						try :
							#print "vlam = ", vmvlans[i]
							if vmvlans[i] == " " :
								continue
							if vmvlans[i] == "0" :
								continue
							x = string.atoi("0x" + vmvlans[i], 16)
							if x != 0:
								k = 0
								while x != 0 :
									y = x % 2
									x = x / 2
									if y == 1 :
										ret[oid].append(str(j*4 + 4-k))
									k = k + 1
							j = j + 1
						except :
							pass
			if ret:
				logScanMsg(2, 'Got VLAN Details - %s' %`ret`, self.module_name)
			return ret
		except :
			return {}

	def getVRFDetails(self):
		vrfInfo = {}
		# Scan Cisco VRF MIB [1.3.6.1.4.1.9.9.711]
		# Get VRF Name from cvVrfName 1.3.6.1.4.1.9.9.711.1.1.1.1.2
		# 			Response: 1.3.6.1.4.1.9.9.711.1.1.1.1.2.<vrfindex>: <vrf name>
		# Get VRF Index to Interface Index Mapping using cvVrfInterfaceType 1.3.6.1.4.1.9.9.711.1.2.1.1.2
		# 			Response: 1.3.6.1.4.1.9.9.711.1.2.1.1.2.<vrfindex>.<ifindex>: <vrf if type>
		# 			Split ifindex from the response OID
		# 			for every <vrfindex>, multiple <ifindex> are assoicated
		# OIDs used
		self.logMsg('Scanning Cisco VRF Details')
		cvVrfName = ".1.3.6.1.4.1.9.9.711.1.1.1.1.2"
		cvVrfInterfaceType = ".1.3.6.1.4.1.9.9.711.1.2.1.1.2"
		# Get VRF Name
		try:
			vrf_table = self.getSNMPTable([cvVrfName])
		except:
			vrf_table = []
		if vrf_table:
			# Construct VRF Index to Name Map
			vrf_index_name_map = {}
			for vrf in vrf_table:
				vrf_index = vrf[0].oid.split('.')[-1]
				vrf_name = vrf[0].value
				vrf_index_name_map[vrf_index] = vrf_name
			logScanMsg(2, 'Got VRF Index & Name Map - %s' %`vrf_index_name_map`, self.module_name)
			# get Interface to VRF Index
			try:
				vrf_if_table = self.getSNMPTable([cvVrfInterfaceType])
			except:
				vrf_if_table = []
			if vrf_if_table:
				for vrf_if in vrf_if_table:
					vrf_index = vrf_if[0].oid.split('.')[-2]
					vrf_if_index = vrf_if[0].oid.split('.')[-1]
					vrfInfo[vrf_if_index] = vrf_index_name_map.get(vrf_index)
			logScanMsg(2, 'Got VRF Details - %s' %`vrfInfo`, self.module_name)
		return vrfInfo

	def scanPowerAndFan(self):
		ret = []
		try:
			self.logMsg("Scanning for Entity Mibs for Power and Fan")
			try:
				entity_table = self.getSNMPTable(['1.3.6.1.2.1.47.1.1.1.1.2', '1.3.6.1.2.1.47.1.1.1.1.3', '1.3.6.1.2.1.47.1.1.1.1.7'])
			except:
				self.logMsg("Device doesn't support Entity MIB")
				entity_table = None
			if entity_table:
				mibViewController = loadMIB('CISCO-ENTITY-VENDORTYPE-OID-MIB')
				for each_ins in entity_table:
					entity_oid = ''
					profile = ''
					content_type = each_ins[1].value
					content_descr = string.strip(each_ins[0].value)
					content_name = string.strip(each_ins[2].value)
					_content_type, component_type = self.getContentType(content_type, mibViewController)
					if component_type.lower().find('powersupply') != -1:
						profile = 'ciscopower.cfg'
					elif component_type.lower().find('fan') != -1:
						profile = 'ciscofan.cfg'
					if profile:
						entity_oid = each_ins[0].oid[len('1.3.6.1.2.1.47.1.1.1.1.2')+1:]
						params = {'oidIndex': entity_oid}
						if profile == 'ciscopower.cfg':
							ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.9.9.117.1.1.2.1.1.%s' %entity_oid, '1.3.6.1.4.1.9.9.117.1.1.2.1.2.%s' %entity_oid])
							if ins and ins[0].value != 'noSuchInstance':
								params['power_oid'] = 1
							else:
								ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.9.9.117.1.2.1.1.1.%s' %entity_oid, '1.3.6.1.4.1.9.9.117.1.2.1.1.2.%s' %entity_oid])
								if ins and ins[0].value != 'noSuchInstance':
									params['power_oid'] = 0
						else: #if profile == 'ciscofan.cfg':
							ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.9.9.117.1.4.1.1.1.%s' %entity_oid, '1.3.6.1.4.1.9.9.117.1.4.1.1.2.%s' %entity_oid])
							if ins and ins[0].value != 'noSuchInstance':
								params['fan_oid'] = 1
							else:
								ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.9.9.117.1.2.1.1.1.%s' %entity_oid, '1.3.6.1.4.1.9.9.117.1.2.1.1.2.%s' %entity_oid])
								if ins and ins[0].value != 'noSuchInstance':
									params['fan_oid'] = 0
						ret.append(LearnedResource(self.addr, content_name, component_type, content_descr, self.snmp_profile, profile,
							resource_alias=content_descr, poll_params=params))
						self.logMsg("Obtained OIDs for CPU / Memory / Environment Parameters - %s"%params)
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanPowerAndFan of Juniper Ex Scanner --- %s"%(msg), self.module_name)
		except :
			logScanExceptionMsg(4, "Exception in scanPowerAndFan of Juniper Ex Scanner ", self.module_name)
		return ret

	def getContentType(self, content_type_oid, mibViewController):
		try:
			oid, label, suffix = mibViewController.getNodeName(tuple(map(lambda z: int(z), content_type_oid.split('.'))))
			content_type = label[-1][3:]
			component_type = label[-2][3:]
			return content_type, component_type
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in getContentType OID resolving - %s for %s' %(msg, content_type_oid), self.module_name)
		return 'Unknown'

	def getEntityVendorTypeMIBName(self):
		return 'CISCO-ENTITY-VENDORTYPE-OID-MIB'

	def scanHost(self):
		# overridden method to avoid scanning of Host MIB.
		return []

	def scanTemperature(self):
		#Nexus devices 
		ret = []
		params = {}
		name_map = {}
		try:
			try:
				ins = self.getSNMPTable(['.1.3.6.1.2.1.47.1.1.1.1.2'])
			except:
				ins = None
			if ins:
				
				for each_ins in ins:
					value= each_ins[0].value
					oid = each_ins[0].oid.split('.')[-1]
					if not any (x in value for x in ['Transceiver','Linecard']):
						name_map[oid]=value
			try:
				ins = self.getSNMPTable(['.1.3.6.1.4.1.9.9.91.1.1.1.1.1','.1.3.6.1.4.1.9.9.91.1.1.1.1.4'])
			except:
				ins = None
			if ins:
				for each_ins in ins:
					value = each_ins[0].value
					oid = each_ins[1].oid.split('.')[-1]
					if safe_int(value)==8:
						if str(oid) in name_map.keys():
							params['oidIndex']=oid
							ret.append(LearnedResource(self.addr, "%s"%name_map.get(oid), "Temperature", "Temperature", self.snmp_profile, 'ciscotemperature.cfg',
							active=1,oid_index=oid, poll_params=params))
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanTemperature of Cisco Scanner --- %s"%(msg), self.module_name)
		except :
			logScanExceptionMsg(4, "Exception in scanTemperature of Cisco Scanner ", self.module_name)
		return ret



	def scanOthers(self):
		ret = []
		try:
			if safe_int(self.discovery_options.get('environment')):
				self.logMsg('Scanning Cisco Environment (Power & Fan)')
				ret += self.scanPowerAndFan()
			if safe_int(self.discovery_options.get('jitter')):
				self.logMsg('Scanning Cisco IPSLA')
				ret += self.scanIPSLA()
				self.logMsg('Found %s Cisco IPSLA configurations'%len(ret))
			if safe_int(self.discovery_options.get('qos')):
				self.logMsg('Scanning Cisco CB QoS MIB')
				cbqos = self.scanCBQoS()
				self.logMsg('Found %s Cisco CB QoS Policies'%len(cbqos))
				if cbqos:
					ret += cbqos
			# For IPSec Tunnels
			ret += self.scanIPSecTunnelMIB()
			ret += self.scanOpticalInterface()
			#Nexus devices
			ret += self.scanTemperature()
			# #Added For Cisco Catalyst
			# if maxInputStats.LEARN_CISCO_CATALYST_RESOURCE == 1:
			# 	ret += self.addCiscoCatalyst()
			# if maxInputStats.LEARN_CISCO_USAGE_RESOURCES == 1:
			# 	ret += self.addCiscoDSUsage()
			ret+= self.scanEIGRPResources()
			print len(ret)

			if self.system_values.get('description','').lower().find('isr software') != -1 :
				ret.extend(self.scanISRDeviceTemperature())
				self.logMsg('scanISRDeviceTemperature %s '%(len(ret)))
			
			if self.isWlcDevice() :   # Checking if the Device is a Cisco Controller
				ret += self.ciscoWlcDeviceScan()
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanOthers of Cisco Scanner --- %s"%(msg), self.module_name)
		except :
			logScanExceptionMsg(4, "Exception in scanOthers of Cisco Scanner ", self.module_name)
		ret = filter(lambda a : a, ret)
		return ret

	def scanISRDeviceTemperature(self):
		try:
			ret = []
			self.logMsg('Scanning for the cisco isr Temperature resource .')
			resource_params = {}
			temp_oid_response = self.getSNMPTable(['1.3.6.1.2.1.47.1.1.1.1.2'])
			if temp_oid_response :
				for oid_response in temp_oid_response :
					temp_res_value = oid_response[0].value
					if temp_res_value.lower().strip().find('temp: internal') != -1  : #or temp_res_value.lower().find('temp: temp') != -1 :
						resource_params['temp_oid'] = chopRight(oid_response[0].oid , '1.3.6.1.2.1.47.1.1.1.1.2.' )
					elif  temp_res_value.lower().strip().find('temp: cpu') != -1 :
						resource_params['temp_cpu'] = chopRight(oid_response[0].oid , '1.3.6.1.2.1.47.1.1.1.1.2.' )
				if resource_params :
					ret.append(LearnedResource(self.addr, "ISR_Temperature" , "Temperature", '' , self.snmp_profile , "ciscoisrtemp.cfg",'' , poll_params=resource_params ))
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanISRDeviceTemperature of Cisco Scanner --- %s"%(msg), self.module_name)
			return []
		return ret

	def scanEIGRPResources(self):
		try:
			self.logMsg('Scanning scanEIGRPResources .... ')
			eigrp_map_dict = {}
			ret = [] 
			ipAdEntAddr = "1.3.6.1.2.1.4.20.1.1"
			ipAdEntIfIndex = "1.3.6.1.2.1.4.20.1.2"
			peer_hex_ip_addr_oid = "1.3.6.1.4.1.9.9.449.1.4.1.1.3"

			peer_hex_ip_addr_res = self.getSNMPTable([peer_hex_ip_addr_oid])
			peer_if_index_res = self.getSNMPTable(["1.3.6.1.4.1.9.9.449.1.4.1.1.4"])

			start_index = len(peer_hex_ip_addr_oid)+1
			ipAdEntAddr_res = self.getSNMPTable([ipAdEntAddr])
			if ipAdEntAddr_res :
				ipAdEntAddr_res_dict = {}
				map(lambda a : ipAdEntAddr_res_dict.update({chopRight(a[0].oid,ipAdEntAddr+'.') : a[0].value })  , ipAdEntAddr_res )

			ipAdEntIfIndex_res = self.getSNMPTable([ipAdEntIfIndex])			
			if ipAdEntIfIndex_res :
				ipAdEntIfIndex_res_dict = {}
				map(lambda a : ipAdEntIfIndex_res_dict.update({ a[0].value : chopRight(a[0].oid,ipAdEntIfIndex+'.')})  , ipAdEntIfIndex_res )

			# Using already defined function.
			self.getInventoryInfoMappingDict(peer_hex_ip_addr_res , start_index , "peer_ip", ret_dict=eigrp_map_dict)
			self.getInventoryInfoMappingDict(peer_if_index_res , start_index , "peer_ifIndex", ret_dict=eigrp_map_dict)
			self.logMsg('Scanning scanEIGRPResources ....number of response %s  '%(len(eigrp_map_dict) ))
			if eigrp_map_dict :
				for oid_index,resources_info in eigrp_map_dict.iteritems() :
					remote_addr_value = resources_info.get("peer_ip")
					remote_if_index = resources_info.get("peer_ifIndex")
					params = {}
					if remote_addr_value and remote_if_index :
						remote_addr = string.join([str(int(octet, 16)) for octet in remote_addr_value.split(':')],'.')
						interface_ip_addr = ipAdEntAddr_res_dict.get( ipAdEntIfIndex_res_dict.get(remote_if_index, '') , '' )
						print interface_ip_addr
						if remote_addr and interface_ip_addr :
							params = { "oidIndex" : oid_index }	
							resources_params = { "ip_addr" : interface_ip_addr , "remote_addr" : remote_addr	}				
							ret.append(LearnedResource(self.addr, "EIGRP / eigrp_%s" %remote_addr.replace(".","_"), "EIGRP Status", "Remote Address - %s" %remote_addr, self.snmp_profile, "ciscoeigrpmon.cfg",resource_alias=remote_addr , poll_params=params )) 
		except Exception,msg :
			print msg
			logScanExceptionMsg(4, "Exception in scanEIGRPResources of Cisco Scanner --- %s"%(msg), self.module_name)
			return []
		return ret

	def scanIPSecTunnelMIB(self):
		ret = []
		try:
			self.logMsg('Scanning Cisco IPSec Tunnel Details')
			cikeTunRemoteAddr = "1.3.6.1.4.1.9.9.171.1.2.3.1.8"
			cikeTunRemoteName = "1.3.6.1.4.1.9.9.171.1.2.3.1.9"
			try:
				tunnel_table = self.getSNMPTable([cikeTunRemoteAddr, cikeTunRemoteName])
			except:
				tunnel_table = []
			if tunnel_table:
				logScanMsg(2, 'Got Tunnel Details - %s' %len(tunnel_table), self.module_name)
				for tunnel_info in tunnel_table:
					remote_ip = self.verifySNMPResponse(tunnel_info[0].value)
					remote_name = self.tryHexToAscii(self.verifySNMPResponse(tunnel_info[1].value))
					# oid_index = string.split(tunnel_info[0].oid, '.')[-1]
					params = {}
					# params['oidIndex'] = oid_index
					params['remote_addr'] = remote_ip
					tunnel_name = remote_ip
					if remote_ip != remote_name:
						tunnel_name = '%s-%s' %(remote_name, remote_ip)
					ret.append(LearnedResource(self.addr, "IPSec/%s" %tunnel_name, "IPSec Tunnel", "IPSec Tunnel - %s" %tunnel_name, self.snmp_profile, "ciscoipsectunnel.cfg", poll_params=params))
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in scanIPSecTunnelMIB - %s' %msg, self.module_name)
		except:
			logScanExceptionMsg(4, 'Exception in scanIPSecTunnelMIB', self.module_name)
		return ret
		
	def scanOpticalInterface(self):
		try:
			logScanMsg(4, "Cisco scanOpticalInterface - OpticalInterface discovery - %s"%self.addr, self.module_name)
			self.logMsg('Scanning Optical Interfaces for Cisco')
			ret = []
			entity_oids = ['.1.3.6.1.2.1.47.1.1.1.1.2', '.1.3.6.1.2.1.47.1.1.1.1.4', '.1.3.6.1.2.1.47.1.1.1.1.7']
			entity_ret = self.getSNMPTable(entity_oids)
			oid_name_map = {}
			oidmap_dict = {}
			for et in entity_ret:
				soid1 = et[1].oid.split('.')[-1]
				stype1 = et[1].value
				soid2 = et[2].oid.split('.')[-1]
				stype2 = et[2].value
				oidmap_dict[soid1] = stype1
				oid_name_map[soid2] = stype2
			resource_map = {}
			for et in entity_ret:
				soid = et[0].oid.split('.')[-1]
				stype = et[0].value
				oid1 = oidmap_dict.get(soid)
				oid2 = oidmap_dict.get(oid1)
				oid3 = oidmap_dict.get(oid2)
				resource = oid_name_map.get(oid3)
				# print resource, "<< resource"
				if resource not in resource_map:
					resource_map[resource] = {}
				soid0 = et[0].oid.split('.')[-1]
				stype0 = et[0].value
				resource_map[resource][stype0] = soid0
			# print "resource_map >>", resource_map
			for interface_name, data in resource_map.iteritems(): 
				# print "resname >> %s - %s " % (interface_name, json.dumps(data, indent=4))
				if "Transceiver Rx Power Sensor" in data or "Transceiver Rx Power Sensor" in data:
					# add resource
					res_name = "OpticalInterfaces__dir__%s" % interface_name
					poll_params = {"interface_name":re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', interface_name),"device_type":"Cisco"}
					poll_params['rxOID'] = data.get("Transceiver Rx Power Sensor")
					poll_params['txOID'] = data.get("Transceiver Tx Power Sensor")
					poll_params['poll_period'] = 3600
					ret.append(LearnedResource(self.addr, res_name, "Optical Interface", 'Optical Interface', self.snmp_profile, 'opticalinterface_cisco.cfg',active=1, poll_params=poll_params))
					logScanMsg(4, "Adding Cisco OpticalInterface  - %s  - %s"%(self.addr, res_name),self.module_name)
			return ret
		except Exception, msg:
			logScanExceptionMsg(4, "Exception in Cisco scanOpticalInterface OpticalInterface - %s %s"%(self.addr, msg), self.module_name)
			return []
		except:
			logScanExceptionMsg(4, "Unkown Exception in Cisco scanOpticalInterface OpticalInterface - %s"%(self.addr), self.module_name)
		return []


	def isWlcDevice(self) :
		# small Function to check device is controller or not 
		try:
			ret = 0
			try:
				result = self.getSNMPTable(['.1.3.6.1.4.1.14179.1.1.5.1'])
			except:
				return ret
			if result and result[0][0].value != "noSuchObject" :
				logMsg(4, "----Calling ciscoWlcDeviceScan Scanner-----", "Scanner")
					#############################################
					# agentCurrentCPUUtilization	1.3.6.1.4.1.14179.1.1.5.1
					# agentTotalMemory agentTotalMemory	1.3.6.1.4.1.14179.1.1.5.2
					# agentFreeMemory agentFreeMemory	1.3.6.1.4.1.14179.1.1.5.3
				ret = 1
		except Exception, msg:
			logExceptionMsg(4, 'Exception in Cisco Scanner API - Device Scan - %s' %msg, 'Scanner')
			return 0
		return ret			

	def ciscoWlcDeviceScan(self) :
		ret = []
		logMsg(4, "Inside ciscoWlcDeviceScan Scanner", "Scanner")
		parameters = ""	
		try:
			try:
				tempres=[]
				tempres.append(LearnedResource(self.addr,'AC Details', 'AC Details' ,'', self.snmp_profile,'CiscoAC.cfg',resource_alias="", resource_params={}, poll_params={}))
				tempres.append(LearnedResource(self.addr,'AP_Clients_Status', 'Clients Status' ,'', self.snmp_profile,'CiscoClientsStatus.cfg',resource_alias="", resource_params={}, poll_params={}))
				tempres.append(LearnedResource(self.addr,'Rouge_AP', 'Rouge_AP' ,'', self.snmp_profile,'CiscoAP_Rouge.cfg',resource_alias="", resource_params={}, poll_params={}))
				tempres.append(LearnedResource(self.addr,'Rouge_AP_Clients', 'Rouge_AP_Clients' ,'', self.snmp_profile,'CiscoAP_RougeClient.cfg',resource_alias="", resource_params={}, poll_params={}))
				ret.extend(tempres)
				self.logMsg("CiscoWLCScannerAPI Scanner In learning Controller resources : %s "%(`len(ret)`))
			except Exception,msg:
				logExceptionMsg(4, "Exception in CiscoWLCScannerAPI Scanner In learning other Controller resources --- %s"%(msg), "Scanner")
			# CSV reading for additional info as of now should only be done by UI
			resource_mannual_inventoryInfo = [] # self.readMannualInventoryInfoFromCsv()
			# hostname = ap_name , model = ap_model , mac = ap_mac , syslocation= ap_location , 
			ineventory_oid_map = {\
			"hostname" : ".1.3.6.1.4.1.14179.2.2.1.1.3",\
			"model" : ".1.3.6.1.4.1.14179.2.2.1.1.16",\
			"serial_number" : ".1.3.6.1.4.1.14179.2.2.1.1.17",\
			"mac" : ".1.3.6.1.4.1.14179.2.2.1.1.33",\
			"syslocation" : ".1.3.6.1.4.1.14179.2.2.1.1.4",\
			"ip_addr" : ".1.3.6.1.4.1.14179.2.2.1.1.19",\
			"os_version"  : ".1.3.6.1.4.1.14179.2.2.1.1.31"\
			}
			
			self.ap_inventoryDict = {} 
			snmpresult  = self.getSNMPTable([ineventory_oid_map.get('hostname')])

			if snmpresult and snmpresult != -1 :
				for inventoryName,oids in ineventory_oid_map.items():
					try:
						temp_resultslist = self.getSNMPTable([oids])
						self.getInventoryInfoMappingDict(temp_resultslist,len(oids),inventoryName,ret_dict=self.ap_inventoryDict)
					except Exception,msg:
						logExceptionMsg(4, "Exception in CiscoWLCScannerAPI   while getting Ap inventory Details Scanner --- %s"%(msg), "Scanner")				
				try :
					count,oidIndexList =0,[] # used for  testing
					oidIndexs,oidToIgnore = '',len(ineventory_oid_map.get('hostname'))
					self.logMsg("CiscoWLCScannerAPI Scanner Number Of Access Point : %d snmpresult for res %s "%(len(snmpresult),self.ap_inventoryDict))
					for i in snmpresult:
						oidIndexs,snmpresponse = str(i[0].oid)[oidToIgnore:],i[0].value
						resname = self.ap_inventoryDict.get(oidIndexs,{}).get('hostname','')
						resource_params ={}
						if not resname :
							try:
								# ap_nameOid = '.1.3.6.1.4.1.14179.2.2.1.1.3.'+oidIndexs
								resname = self.multiSNMPGet("get",['.1.3.6.1.4.1.14179.2.2.1.1.3.'+oidIndexs])[0].value
								self.logMsg("CiscoWLCScannerAPI Scanner Resource New Ap Name  : %s and Interface ResName  : %s"%(`resname`,`interface_resname`))
							except:
								self.logMsg("CiscoWLCScannerAPI Scanner Droping the resource because name is not proper  : %s "%(`oidIndexs`))
								continue
						# updating the resource_params for this resource
						for key,value in self.ap_inventoryDict.get(oidIndexs,{}).items():
							if key and value :
								resource_params.update({key:value})
						resource_params.update({"poll_addr":self.ap_inventoryDict.get(oidIndexs,{}).get('ip_addr','') ,"dest_addr":self.addr,'make':'Cisco','alias':resname,'device_type':'Access Point','location':self.ap_inventoryDict.get(oidIndexs,{}).get('syslocation','')})
						# some res info are common for res and node and node_obj should be formed here itself
						# print '--resource_params >> > ',resource_params

						params = {"oidIndex":str(oidIndexs)}
						self.logMsg("CiscoWLCScannerAPI Scanner Resource resource_params %s and params  : %s "%(`resource_params`,`params`))
						#Avoid duplication
						if oidIndexs not in oidIndexList :
							self.logMsg("CiscoWLCScannerAPI Scanner Resource OidIndex Formation : %s , ResourceName : %s "%(`oidIndexs`,`resname`))
							count+=1
							res = LearnedResource(self.ap_inventoryDict.get(oidIndexs,{}).get('ip_addr',''), resname, 'Access Point' ,'location = %s'%self.ap_inventoryDict.get(oidIndexs,{}).get('syslocation',''), self.snmp_profile,'CiscoAP.cfg',resource_alias=self.ap_inventoryDict.get(oidIndexs,{}).get('hostname',''), resource_params=resource_params, poll_params=params,node_obj = resource_params)
							ret.append(res)
							# Ap interfaces will be having there own poll_params
							ap_interfaces = self.getWLCAPInterfaces(oidIndexs,resource_params,poll_params={},ap_name=resname) 
							if ap_interfaces:
								ret.extend(ap_interfaces)
							# if count == 10:return ret
							oidIndexList.append(oidIndexs)
					self.logMsg("CiscoWLCScannerAPI Scanner Number Of Access Point Discovered : %d "%(safe_int(count)))
				except Exception,msg:
					logExceptionMsg(4, "Exception in CiscoWLCScannerAPI Scanner --- %s"%(msg), "Scanner")
		except Exception,msg :
			logExceptionMsg(4, "Exception in CiscoWLCScannerAPI Scanner --- %s"%(msg), "Scanner")
		return ret

	def getWLCAPInterfaces(self,oidIndexs,resource_params={},poll_params={},ap_name=""):
		try:
			# Appending the ap name so that the auto_importToResServere function of autodiscovery sould 
			# not rename it to dup and name will be unique
			ret = []
			self.logMsg(" Entering CiscoWLCScannerAPI getWLCAPInterfaces oidIndex  : %s "%(oidIndexs))
			if oidIndexs and oidIndexs != -1:
				oid_query = '.1.3.6.1.4.1.9.9.513.1.2.2.1.2'
				ap_interfaceNameOid = oid_query+"."+oidIndexs
				apinterface_snmpresult = self.getSNMPTable([ap_interfaceNameOid])
				# for some AP's found more than one interface so table
				for interfaces in apinterface_snmpresult:
					try:
						params = {}
						responseOid,responseValue = interfaces[0].oid,interfaces[0].value
						oidIndexForPollParams = oidIndexs+'.'+str(responseOid)[len(ap_interfaceNameOid):]
						resname = responseValue
						if oidIndexForPollParams and responseOid and responseValue :
							params.update({'oidIndex': oidIndexForPollParams ,"speed":1000000000})
							# resource_params.update({'alias':""})						
							resource = LearnedResource(self.ap_inventoryDict.get(oidIndexs,{}).get('ip_addr',''), ap_name+"_"+resname , 'Ethernet' ,'location = %s'%self.ap_inventoryDict.get(oidIndexs,{}).get('syslocation',''), self.snmp_profile,'CiscoApifmib.cfg',resource_alias='', resource_params=resource_params, poll_params=params ,node_obj = resource_params)
							ret.append(resource)
					except Exception,msg:
						logExceptionMsg(4, "Exception in getWLCInterfaces in converting response to resource CiscoWLCScannerAPI Scanner --- %s"%(msg), "Scanner")
			self.logMsg("CiscoWLCScannerAPI getWLCAPInterfaces Found number of interfaces : %s "%(`len(ret)`))
		except Exception as msg:
			logExceptionMsg(4, "Exception in getWLCInterfaces CiscoWLCScannerAPI Scanner --- %s"%(msg), "Scanner")
		return ret

	def getInventoryInfoMappingDict(self,snmpresult,start_index,key='',end_index=0, ret_dict={}):
		# finalresnamedict = {}
		try:
			# ap_inventoryDict will be having {oidIndexOfAp:{inventorytype:value}}
			print '\n snmpresult getResnameDict ',len(snmpresult)
			for i in snmpresult :
				if not end_index:
					oidIndexs,value = str(i[0].oid)[start_index:],str(i[0].value)
				else :
					oidIndexs,value = str(i[0].oid)[start_index:end_index],str(i[0].value)
				if not ret_dict.get(oidIndexs,{}):
					ret_dict.update({oidIndexs:{}})
				# if value and value != -1:
				# 	self.ap_inventoryDict.get(oidIndexs,{}).update({key:value})
				# else:
				# 	self.ap_inventoryDict.get(oidIndexs,{}).update({key:""})
				value = iif(value  , value, "")
				ret_dict.get(oidIndexs,{}).update({key:value})

			self.logMsg("CiscoWLCScannerAPI Scanner getInventoryInfoMappingDict : %s "%(`len(ret_dict)`))
		except Exception,msg:
			logExceptionMsg(4, "Exception in getInventoryInfoMappingDict CiscoWLCScannerAPI Scanner --- %s"%(msg), "Scanner")
		return ret_dict

	#Append the resource to ret dont assign it.
	def addCiscoCatalyst(self) :
		self.logMsg("Scanning for Cisco Catalyst Mibs")
		#Cisco Catalyst Chassis
		ins = self.getSNMPTable([".1.3.6.1.4.1.9.5.1.2.1"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				params = {}
				params['oidIndex'] = oid
				# ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Catalyst Chassis", 'Chassis__dir__Chassis_%s'%oid, 'CiscoCatalystChassis.cfg'))
		else:
			self.logMsg("Cannot find the Chassis instance from Cisco Catalyst Enterprise MIB")
	
		#Cisco Catalyst Port
		ins = self.getSNMPTable([".1.3.6.1.4.1.9.5.1.4.1.1.2"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Catalyst Port", 'Port__dir__Port_%s'%oid, 'CiscoCatalystPort.cfg'))
		else:
			self.logMsg("Cannot find the Port instance from Cisco Catalyst Enterprise MIB")

		#Cisco Catalyst Port Security
		ins = self.getSNMPTable([".1.3.6.1.4.1.9.5.1.10.1.1.2"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Catalyst PortSecurity", 'Port__dir__PortSecurity_%s'%oid, 'CiscoCatalystPortSecurity.cfg'))
		else:
			self.logMsg("Cannot find the PortSecurity instance from Cisco Catalyst Enterprise MIB")

		#Cisco Catalyst Port Capability
		ins = self.getSNMPTable([".1.3.6.1.4.1.9.5.1.19.1.1.2"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner, "Cisco Scanner", addr, community, add_parameters,"Catalyst PortCapability", 'Port__dir__PortCapability_%s'%oid, 'CiscoCatalystPortCapability.cfg'))
		else:
			scanner.logMsg("Cannot find the Port Capability from Cisco Catalyst Enterprise MIB")

		#Cisco Catalyst VLAN Port
		ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.5.1.9.3.1.2"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Catalyst VLANPort", 'VLAN__dir__Port_%s'%oid, 'CiscoCatalystVlanPort.cfg'))
		else:
			scanner.logMsg("Cannot find the VLAN Port from Cisco Catalyst Enterprise MIB")

		#Cisco Catalyst VLAN Trunk Mapping
		ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.5.1.9.8.1.2"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Catalyst VLANTrunkMapping", 'VLAN__dir__TrunkMapping_%s'%oid, 'CiscoCatalystVlanTrunkMapping.cfg'))
		else:
			scanner.logMsg("Cannot find the VLAN Trunk Mapping instance from Cisco Catalyst Enterprise MIB")

		#Cisco Catalyst VMPS
		ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.5.1.9.4.1.1"])
		if ins:
			for each_ins in ins:
				oid = each_ins[0].oid.split('.')[-1]
				value = each_ins[0].value
				add_parameters = parameters + ',oidIndex=%s'%oid
				ret.append(self.addResource(scanner, "Cisco Scanner", addr, community, add_parameters,"Catalyst VMPS", 'VMPS__dir__VMPS_%s'%oid, 'CiscoCatalystVmps.cfg'))
		else:
			scanner.logMsg("Cannot find the VMPS instance from Cisco Catalyst Enterprise MIB")

	def addCiscoDSUsage(self, scanner, addr, community, snmpPort, ret):
		try:
			scanner.logMsg("Scanning for ciscoPopMgmtMIB  Mibs")
			parameters = ""
			# For SNMPv3 Support
			if scanner.username :
				parameters = "username=%s,contextname=%s,securitylevel=%s,authType=%s,authPass=%s,privType=%s,privPass=%s," %(scanner.username, scanner.contextname, scanner.securitylevel, scanner.authType, scanner.authPass, scanner.privType, scanner.privPass)
			if snmpPort != 161 :
				parameters += "SNMPPort=%d," % snmpPort
			#Added for adding system location, oid value, description, contact and node type info to params field
			try:
				parameters = parameters + "loc=%s,sysObjectId=%s,descr=%s,contact=%s,node_type=%s,device_name=%s,os_name=%s"%(scanner.location,scanner.oid,scanner.descr,scanner.contact,scanner.node_type,scanner.device_name,scanner.os_name)
			except:
				parameters = parameters + "loc=,sysObjectId=enterprises.9,descr=,contact=,node_type=ciscoPopMgmt,device_name=,os_name="
			#Cisco CPM DS0 Usage
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.10.19.1.1.1"])
			if ins:
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, parameters,"Cisco cpm DS0 Usage ", 'Cisco cpmDS0Usage', 'ciscocpmds0usage.cfg'))
			else:
				scanner.logMsg("Cannot find the cpm DS0 Usage instance from Cisco Cisco ciscoPopMgmt Enterprise MIB")		
			#Cisco CPM DS1 DS0 Usage
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.10.19.1.1.9.1"])
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco cpmDS1DS0Usage", 'Cisco__cpmDS1DS0Usage__%s'%oid, 'ciscocpmDS1DS0UsageEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the cpmDS1DS0Usage instance from Cisco Cisco ciscoPopMgmt Enterprise MIB")
			#Cisco Environment Monitoring Temperature Status Entry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.9.13.1.3.1.1"])
			logMsg(4, "ciscoEnvMonTemperatureStatusEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"ciscoEnvMonTemperatureStatusEntry", 'ciscoEnvMonTemperatureStatusEntry__%s'%oid, 'ciscoenvmontemperaturestatus.cfg'))
			else:
				scanner.logMsg("Cannot find the ciscoEnvMonTemperatureStatusEntry instance from Cisco ciscoEnvMonMIB Enterprise MIB")
			#Cisco Environment Monitoring Fan Status Entry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.9.13.1.4.1.1"])
			logMsg(4, "ciscoEnvMonFanStatusEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"ciscoEnvMonFanStatusEntry", 'ciscoEnvMonFanStatusEntry__%s'%oid, 'ciscoEnvMonFanStatus.cfg'))
			else:
				scanner.logMsg("Cannot find the ciscoEnvMonFanStatusEntry instance from ciscoEnvMonMIB Enterprise MIB")
			#Cisco Environment Monitoring Supply Status Entry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.9.13.1.5.1.1"])
			logMsg(4, "ciscoEnvMonSupplyStatusEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"ciscoEnvMonSupplyStatusEntry", 'ciscoEnvMonSupplyStatusEntry__%s'%oid, 'ciscoEnvMonSupplyStatus.cfg'))
			else:
				scanner.logMsg("Cannot find the ciscoEnvMonSupplyStatusEntry instance from Cisco ciscoEnvMonMIB Enterprise MIB")
			#Cisco lsystem
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.2.1.45"])
			if ins:
				for each_ins in ins:
					value = each_ins[0].value
					add_parameters = parameters
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco lsystem", 'Buffer', 'CiscoLsystem.cfg'))
			else:
				scanner.logMsg("Cannot find the lsystem instance from Cisco Enterprise MIB")
			#Cisco lifEntry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.2.2.1.1.1"])
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco lifEntry", 'lifEntry_%s'%oid, 'CiscolifEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the lifEntry instance from Cisco  Enterprise MIB")
			#Cisco dot3StatsEntry
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.10.7.2.1.1"])
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco dot3StatsEntry", 'Fa_%s_dot3Stats'%oid, 'dot3StatsEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the dot3StatsEntry instance from Cisco  Enterprise MIB")
			#Cisco ciscoMemoryPoolEntry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.9.48.1.1.1.5"])
			if ins:
				value = each_ins[0].value
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco ciscoMemoryPoolEntry", 'Memory_Pool', 'CiscoMemoryPoolEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the ciscoMemoryPoolEntry instance from Cisco  Enterprise MIB")
			#Cisco dsx1CurrentIndex
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.10.18.7.1.1"])
			logMsg(4, "dsx1CurrentIndex ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco dsx1CurrentIndex", 'E1_0_%s'%oid, 'dsx1CurrentEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the dsx1CurrentIndex instance from Cisco  Enterprise MIB")
			#Cisco frCircuitEntry
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.10.32.2.1.1"])
			logMsg(4, "frCircuitEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco frCircuitEntry", 'Frame_Relay_0_%s'%oid, 'frCircuitEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the frCircuitEntry instance from Cisco  Enterprise MIB")
			#Cisco bgpPeerEntry
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.15.3.1.1"])
			logMsg(4, "bgpPeerEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco bgpPeerEntry", 'BGP_NBR_%s'%oid, 'bgpPeerEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the bgpPeerEntry instance from Cisco  Enterprise MIB")
			#Cisco OSPF GeneralGroup
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.14.1.1"])
			logMsg(4, "ospfGeneralGroup ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco OSPF GeneralGroup", 'ospf_group__%s'%oid, 'ospfGeneralGroup.cfg'))
			else:
				scanner.logMsg("Cannot find the ospfGeneralGroup instance from Cisco  Enterprise MIB")
			#Cisco OSPF GeneralGroup
			ins = scanner.getSNMPTable([".1.3.6.1.2.1.14.10.1.1"])
			logMsg(4, "ospfNbrEntry ins --- %s"%(ins), "Cisco Scanner")
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco OSPF NbrEntry", 'ospf_nbr__%s'%oid, 'ospfNbrEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the ospfNbrEntry instance from Cisco  Enterprise MIB")
			#Cisco sysTraffic
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.5.1.1.8"])
			if ins:
				value = each_ins[0].value
				ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco sysTraffic", 'System_Traffic', 'CiscoSystemGrp.cfg'))
			else:
				scanner.logMsg("Cannot find the sysTraffic instance from Cisco  Enterprise MIB")
			#Cisco moduleEntry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.5.1.3.1.1.1"])
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco moduleEntry", 'Module_Entry__%s'%oid, 'CiscoModuleEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the moduleEntry instance from Cisco  Enterprise MIB")
			#Cisco vtpVlanEntry
			ins = scanner.getSNMPTable([".1.3.6.1.4.1.9.9.46.1.3.1.1.1"])
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					add_parameters = parameters + ',oidIndex=%s'%oid
					ret.append(self.addResource(scanner,"Cisco Scanner", addr, community, add_parameters,"Cisco vtpVlanEntry", 'Vlan_Entry__%s'%oid, 'CiscoVTPVlanEntry.cfg'))
			else:
				scanner.logMsg("Cannot find the vtpVlanEntry instance from Cisco  Enterprise MIB")
		except Exception,msg :
			logExceptionMsg(4, "Exception in addCiscoDSUsage of Cisco Scanner --- %s"%(msg), self.module_name)
		except :
			logExceptionMsg(4, "Exception in addCiscoDSUsage of Cisco Scanner ", self.module_name)		

	def addResource(self, scanner, scanner_name, addr, community, parameters, restype, resname, profile) :
		res = LearnedResource(addr, community, resname,
			restype, profile, params = parameters)
		scanner.logMsg("%s : %s Log Added"%(scanner_name, restype))
		return res

	def scanNetworkMemoryInventoryMIB(self, inventoryScan, result,resObj):
		#Scanning Memory MIB
		#[processor memory, NVRAM Size, NVRAM Used]
		try:
			logScanMsg(4, "Inside scanNetworkChassisInventoryMIB of Cisco Scanner", self.module_name)
			oids = [".1.3.6.1.4.1.9.9.195.1.1.1.1",".1.3.6.1.4.1.9.9.195.1.1.1.2",".1.3.6.1.4.1.9.9.195.1.1.1.3"]
			if not result.has_key("Win32_PhysicalMemory"):
				result["Win32_PhysicalMemory"] = {}
			ret_ins = inventoryScan.snmpObj.getSNMPTable(oids)

			capacity = safe_float(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', ret_ins[0][0].value))
			name = "Processor Memory"
			manufacturer = 'Cisco'
			result["Win32_PhysicalMemory"].update({name:{"name":name,'nodeid':inventoryScan.nodeid,"capacity":capacity,"manufacturer":manufacturer,"poller_id":inventoryScan.site_id}})

			capacity = safe_float(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', ret_ins[0][1].value))
			sizeused = safe_float(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', ret_ins[0][2].value))
			name = "NVRAM"
			result["Win32_PhysicalMemory"].update({name:{"name":name,'nodeid':inventoryScan.nodeid,"capacity":capacity,"manufacturer":manufacturer, "sizeused":sizeused,"poller_id":inventoryScan.site_id}})

			logMsg(4, "Exit out of scanNetworkMemoryInventoryMIB of Cisco Scanner", self.module_name)
		except Exception, msg:
			logExceptionMsg(4, "Exception in scanNetworkMemoryInventoryMIB of Cisco Scanner %s"%(msg), self.module_name)
		return result
	
	def scanNetworkDiskInventoryMIB(self, inventoryScan, result,resObj):
		#Scanning Disk MIB
		#[name, capacity]
		try:
			logMsg(4, "Inside scanNetworkDiskInventoryMIB of Cisco Scanner", self.module_name)
			big_oids = ["1.3.6.1.4.1.9.9.10.1.1.2.1.15", "1.3.6.1.4.1.9.9.10.1.1.2.1.16"]
			small_oids = ["1.3.6.1.4.1.9.9.10.1.1.2.1.7", "1.3.6.1.4.1.9.9.10.1.1.2.1.2"]

			if not result.has_key('Win32_LogicalDisk'):
				result["Win32_LogicalDisk"] = {}
			ret_ins_big = inventoryScan.snmpObj.getSNMPTable(big_oids)
			completed_index = {}
			handle_duplicate = {}
			description = "Local Fixed Disk"	

			for each_entry in ret_ins_big:
				oidIndex = splitRight(each_entry[0].oid, '.')[1]
				completed_index[oidIndex] = 1
				name = re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', each_entry[0].value)
				size = safe_float(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', each_entry[1].value))
				volumename = name
				
				if handle_duplicate.has_key(name):
					handle_duplicate[name] += 1
					result["Win32_LogicalDisk"].update({name + "_" + str(handle_duplicate[name]):{"name":name + "_" + str(handle_duplicate[name]),'nodeid':inventoryScan.nodeid,"size":size,"volumename":volumename,"poller_id":inventoryScan.site_id, "description":description}})
				else:
					handle_duplicate[name] = 0
					result["Win32_LogicalDisk"].update({name:{"name":name,'nodeid':inventoryScan.nodeid,"poller_id":inventoryScan.site_id,"size":size,"volumename":volumename,"description":description}})

			ret_ins_small = inventoryScan.snmpObj.getSNMPTable(small_oids)
			for each_entry in ret_ins_small:
				oidIndex = splitRight(each_entry[0].oid, '.')[1]
				if not completed_index.has_key(oidIndex):
					name = re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', each_entry[0].value)
					size = safe_float(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', each_entry[1].value))
					volumename = name		
					result["Win32_LogicalDisk"].update({name:{"name":name,'nodeid':inventoryScan.nodeid,"poller_id":inventoryScan.site_id,"size":size,"volumename":volumename, "description":description}})

			logMsg(4, "Exit out of scanNetworkDiskInventoryMIB of Cisco Scanner", self.module_name)
		except Exception, msg:
			logExceptionMsg(4, "Exception in scanNetworkDiskInventoryMIB of Cisco Scanner %s"%(msg), self.module_name)
		return result

	def scanIPSLA(self):
		ret = []
		self.logMsg("Scanning for CISCO RTTMON Mibs")
		"""
		RTT Types:
			echo(1), 
			pathEcho(2), 
			fileIO(3), 
			script(4), 
			udpEcho(5), 
			tcpConnect(6), 
			http(7), 
			dns(8), 
			jitter(9), 
			dlsw(10), 
			dhcp(11), 
			ftp(12), 
			voip(13), 
			rtp(14), 
			lspGroup(15), 
			icmpjitter(16), 
			lspPing(17), 
			lspTrace(18), 
			ethernetPing(19), 
			ethernetJitter(20), 
			lspPingPseudowire(21)
		"""
		try:
			try:
				#get EchoAdmin 
				EchoAdmin={}
				#Fetch the corresponding row in the EchoAdminTable 
				try:
					result1 = self.getSNMPTable(['.1.3.6.1.4.1.9.9.42.1.2.2.1.6', '.1.3.6.1.4.1.9.9.42.1.2.2.1.18', '.1.3.6.1.4.1.9.9.42.1.2.2.1.2', '.1.3.6.1.4.1.9.9.42.1.2.2.1.9', '.1.3.6.1.4.1.9.9.42.1.2.1.1.3', '.1.3.6.1.4.1.9.9.42.1.2.2.1.17', '.1.3.6.1.4.1.9.9.42.1.2.2.1.2', '.1.3.6.1.4.1.9.9.42.1.2.1.1.6', '.1.3.6.1.4.1.9.9.42.1.2.2.1.3', '.1.3.6.1.4.1.9.9.42.1.2.2.1.5', '.1.3.6.1.4.1.9.9.42.1.2.2.1.1',])
				except:
					logScanExceptionMsg(4,'Exception ',self.module_name)
					return []
				result1_dict = {}
				for res in result1:
					#print  res[0].oid , res[0].value
					for r in res:
						result1_dict.update({r.oid.replace('.iso.org.dod.internet.private.enterprises','.1.3.6.1.4.1') : r.value})
				requiredoidList = {
					"sourceip1":"1.3.6.1.4.1.9.9.42.1.2.2.1.6",
					"packetsize":"1.3.6.1.4.1.9.9.42.1.2.2.1.3",
					"frequency":"1.3.6.1.4.1.9.9.42.1.2.1.1.6",
					"sourceAddr":"1.3.6.1.4.1.9.9.42.1.2.2.1.6",
					"targetAddr":"1.3.6.1.4.1.9.9.42.1.2.2.1.2",
					"tos":"1.3.6.1.4.1.9.9.42.1.2.2.1.9",
					"interpacketinterval":"1.3.6.1.4.1.9.9.42.1.2.2.1.17",
					"DestIp":"1.3.6.1.4.1.9.9.42.1.2.2.1.2",
					"targetport":"1.3.6.1.4.1.9.9.42.1.2.2.1.5",
					"numPackets":"1.3.6.1.4.1.9.9.42.1.2.2.1.18",
					"method":"1.3.6.1.4.1.9.9.42.1.2.2.1.1",
					"admintag":"1.3.6.1.4.1.9.9.42.1.2.1.1.3",
				}
				tos_cos_map = {0: 0, 32: 1, 64: 2, 96: 3, 128: 4, 160: 5, 192: 6, 224: 7}
				EchoAdmin_ins = self.getSNMPTable(['.1.3.6.1.4.1.9.9.42.1.2.1.1.2','.1.3.6.1.4.1.9.9.42.1.2.1.1.4','.1.3.6.1.4.1.9.9.42.1.2.1.1.9'])
				objs = []
				for echoadmin in EchoAdmin_ins:
					obj = {}
					params = {}
					#echoadmin[0].oid	#
					name = echoadmin[0].value
					obj['name'] = name
					#echoadmin[1].oid	#
					type = echoadmin[1].value
					obj['type'] = type
					#echoadmin[2].oid	#
					status = echoadmin[2].value
					obj['status'] = status
					if safe_int(status) == 1 and safe_int(type) in (1, 9, 16):
						# ICMP Echo
						if safe_int(type) == 1:
							obj['profile'] = 'CiscoIPSLARTTJitter.cfg'
							obj['res_type'] = 'ICMP Echo'
						# ICMP Jitter
						elif safe_int(type) == 16:
							obj['profile'] = 'ciscoIPSLAICMPJitter.cfg'
							obj['res_type'] = 'ICMP Jitter'
						# UDP Jitter
						else:
							obj['profile'] = 'CiscoIPSLAJitter.cfg'
							obj['res_type'] = 'UDP Jitter'
						#Add the resource Here to the ret
						oidIndex = echoadmin[0].oid.split('.')[-1]	#Fetch the last element
						params["oidIndex"] = oidIndex
						obj['oidIndex'] = oidIndex
						for key,oid in requiredoidList.items():
							val = result1_dict.get(str(oid)+'.'+str(oidIndex))
							if val == None:
								val = ''
							admintag = ''
							if key == 'admintag' and val:
								admintag = val.strip()
							if key in ['sourceip1','DestIp','targetAddr', 'sourceAddr']:
								val = self.octetToIP(val)
								if val == '0.0.0.0':
									val = addr
							obj[key] = str(val)
							params[key] = str(val)
						obj['params'] = params
						objs.append(obj)
				src_target_objs = classifyObjs(objs, lambda a: (a.get('sourceip1', ''), a.get('targetAddr', '')))
				for (src_ip, target_ip), tos_objs in src_target_objs.items():
					if src_ip == '0.0.0.0':
						src_ip = self.addr
					tos_objs.sort(lambda a, b: cmp(safe_int(a.get('tos', '')), safe_int(b.get('tos', ''))))
					for obj in tos_objs:
						params = obj.get('params', '')
						cos = tos_cos_map.get(safe_int(obj.get('tos')), 0)
						params['cos'] = cos
						admin_tag = obj.get('admintag', '').strip()
						oidIndex = obj.get('oidIndex', '')
						resource_alias = admin_tag
						profile = obj.get('profile', '')
						res_name = '%s-%s-%s' %(src_ip, target_ip, admin_tag)
						res_type = obj.get('res_type', '')
						resource_params = {}
						resource_params['dest_addr'] = target_ip
						resource_params['src_addr'] = src_ip
						ret.append(LearnedResource(self.addr, res_name, res_type, description, self.snmp_profile, profile,
								resource_alias=resource_alias, resource_params=resource_params, poll_params=params
								))
			except Exception, msg:
				logScanExceptionMsg(4,'Exception Occurred in scanning..- %s' %msg, self.module_name)
				self.logMsg("Exception Occurred in scanning EchoAdmin Enterprise MIB - %s" %(msg))
			except:
				logScanExceptionMsg(4,'Exception Occurred in scanning..', self.module_name)
				self.logMsg("Exception Occurred in scanning EchoAdmin Enterprise MIB")
		except Exception, msg :
			logScanExceptionMsg(4, "Exception in cisco Scanner --- %s"%(msg), self.module_name)
		except :
			logScanExceptionMsg(4, "Exception in cisco Scanner ", self.module_name)
		return ret

	def octetToIP(self,val):
		"""Return the string x.x.x.x Representation of the octet string
		"""
		try:
			if len(val) == 4:
				return str(ord(val[0])) + '.' + str(ord(val[1])) + '.' + str(ord(val[2])) + '.' + str(ord(val[3]))
			val1 = val[:]
			val = str(val.strip())
			if val.find(':') != -1:
				return  '.'.join(map(lambda a: str(int(str(a),16)),  val.split(':')))
			return  '.'.join(map(lambda a: str(int(str(a),16)),  val.split(' ')))
		except:
			logScanExceptionMsg(4,'Cannot Convert in to ip address',self.module_name)
			try:
				logScanMsg(4,"Trying with only first four characters",self.module_name)
				val1 = val1[:4]	#Extract the first 4 characters.
				return str(ord(val1[0])) + '.' + str(ord(val1[1])) + '.' + str(ord(val1[2])) + '.' + str(ord(val1[3]))
			except:
				logScanExceptionMsg(4,'Cannot Convert %s into ip address with 4 chars also'%val1,self.module_name)
		return val1

	def scanCBQoS(self):
		ret = []
		try:
			self.logMsg("Starting Cisco CB QOS MIB")
			interfacesifdescr = ['.1.3.6.1.2.1.2.2.1.2']		
			interfacesifdescrTable = self.getSNMPTable(interfacesifdescr)
			interfacesifdescrTableMap = get_table_map(interfacesifdescrTable)		
			interfaceByIndex = interface_index_name_dict(interfacesifdescrTableMap)
			try:
				interfacesifname = ['.1.3.6.1.2.1.31.1.1.1.1']		
				interfacesifnameTable = self.getSNMPTable(interfacesifname)
				interfacesifnameTableMap = get_table_map(interfacesifnameTable)		
				interfaceNameByIndex = interface_index_name_dict(interfacesifnameTableMap)
			except:
				interfaceNameByIndex = {}
			logScanMsg(2, 'Scanned Interface Descr Result - %s' %(`interfaceByIndex`), self.module_name)
			logScanMsg(2, 'Scanned Interface Name Result - %s' %(`interfaceNameByIndex`), self.module_name)
			interface_index_ip_dict = {}
			try:
				interface_ip_index_oid = '1.3.6.1.2.1.4.20.1.2'
				if_index_ip_table = self.getSNMPTable([interface_ip_index_oid])
			except:
				if_index_ip_table = []
			if if_index_ip_table:
				for ip_index in if_index_ip_table:
					oid = ip_index[0].oid
					if_index = ip_index[0].value
					ip_addr = oid[len(interface_ip_index_oid)+1:]
					if if_index not in interface_index_ip_dict:
						interface_index_ip_dict[if_index] = []
					interface_index_ip_dict[if_index].append(ip_addr)
				for if_index in interface_index_ip_dict:
					ips = interface_index_ip_dict[if_index]
					interface_index_ip_dict[if_index] = string.join(ips, ';')
			logScanMsg(2, 'Scanned Interface Index and IP Addr Dict- %s' %(`interface_index_ip_dict`), self.module_name)
			#Changes for the following information in the database
			#.1.3.6.1.4.1.9.9.166.1.1.1.1.4: cbQosIfIndex:gives policyid and applied to which interface
			#.1.3.6.1.4.1.9.9.166.1.1.1.1.3: cbQosPolicyDirection: gives policyid and input/output
			self.logMsg('Scanning For cbQosIfIndex and cbQosPolicyDirection')
			res = self.getSNMPTable(['.1.3.6.1.4.1.9.9.166.1.1.1.1.4','.1.3.6.1.4.1.9.9.166.1.1.1.1.3'])
			"""#Intial table structure for the configuration
			{  policyid:(interface_index,direction_index), ... }	Dictionary creation
			"""
			mapping_table = {}
			for r in res:
				#Get the Key Value for creating the table as mentioned.
				if len(r) > 1:				
					mapping_table.update({r[0].oid.split('.')[-1]:(r[0].value,r[1].value)})
			logScanMsg(2, 'Scanned Result Mapping Table- %s' %(`mapping_table`), self.module_name)
			#Constant Tables : Which Need to be scanned.
			#3.	.1.3.6.1.4.1.9.9.166.1.6.1	-	cbQosPolicyMapCfgTable
			logScanMsg(2, 'Scanning For cbQosPolicyMapCfgTable', self.module_name)
			self.logMsg('Scanning For cbQosPolicyMapCfgTable')
			cbQosPolicyMapCfgTable = self.getSNMPTable(['.1.3.6.1.4.1.9.9.166.1.6.1.1.1'])
			self.logMsg('Scanning For cbQosPolicyMapCfgTable is done. Forming the dictionary')
			#Create the dictionaries of these entries
			cbQosPolicyMapCfgDict = getResultDictFromWalk(cbQosPolicyMapCfgTable)
			logScanMsg(2, 'Scanned Result cbQosPolicyMapCfgDict - %s' %(`cbQosPolicyMapCfgDict`), self.module_name)
			#4.	.1.3.6.1.4.1.9.9.166.1.7.1	-	cbQosCMCfgTable
			self.logMsg('Scanning For cbQosCMCfgTable')
			cbQosCMCfgTable = self.getSNMPTable(['.1.3.6.1.4.1.9.9.166.1.7.1.1.1'])
			self.logMsg('Scanning For cbQosCMCfgTable is done. Forming the dictionary')
			#Create the dictionaries of these entries
			cbQosCMCfgDict = getResultDictFromWalk(cbQosCMCfgTable)
			logScanMsg(2, 'Scanned Result cbQosCMCfgDict - %s' %(`cbQosCMCfgDict`), self.module_name)
			#.1.3.6.1.4.1.9.9.166.1.5.1.1.2:cbQosConfigIndex
			#.1.3.6.1.4.1.9.9.166.1.5.1.1.3:cbQosObjectsType
			#.1.3.6.1.4.1.9.9.166.1.5.1.1.4:cbQosParentObjectIndex
			self.logMsg('Scanning For cbQosConfigIndex, cbQosObjectsType and cbQosParentObjectIndex')
			# self.createSession()
			res = self.getSNMPTable(['.1.3.6.1.4.1.9.9.166.1.5.1.1.2','.1.3.6.1.4.1.9.9.166.1.5.1.1.3','.1.3.6.1.4.1.9.9.166.1.5.1.1.4'])
			self.logMsg('Scanning For cbQosConfigIndex, cbQosObjectsType and cbQosParentObjectIndex is done. Forming the dictionary')
			object_table = getResultDictFromWalk(res)
			logScanMsg(2, 'Scanned Result object_table - %s' %(`object_table`), self.module_name)
			object_names = updateNamesForObjects(res,cbQosPolicyMapCfgDict,cbQosCMCfgDict)
			resource_matrix = {}
			resource_object = {}
			# cbQosObjectType: 1-11
			# 1: policymap, 2: classmap, 3: matchStatement, 4: queueing, 5: randomDetect, 6: trafficShaping, 7: police,
			# 8: set, 9: compression, 10: ipslaMeasure, 11: account

			# currently considered the CIR / PIR specified in bps value.
			# Need to do if CIR / PIR specified in percentage instead of bps.
			police_cfg_table = self.getSNMPTable(['.1.3.6.1.4.1.9.9.166.1.12.1.1.11','.1.3.6.1.4.1.9.9.166.1.12.1.1.2','.1.3.6.1.4.1.9.9.166.1.12.1.1.3', '.1.3.6.1.4.1.9.9.166.1.12.1.1.10'])
			police_info = {}
			for police_cfg in police_cfg_table:
				config_index = chopRight(police_cfg[0].oid, '.')
				police_info[config_index] = {}
				police_info[config_index]['cir'] = police_cfg[0].value
				police_info[config_index]['cbs'] = police_cfg[1].value
				police_info[config_index]['ebs'] = police_cfg[2].value
				police_info[config_index]['pir'] = police_cfg[3].value
			# filter only police qos type data
			# retrive behavior obj config index and parent object oid and value. parent object value maps to class map object id. 
			police_objs = map(lambda a: (a[0].value, a[2].oid, a[2].value), filter(lambda a: a[1].value == '7', res))
			class_map_police_map = {}
			for obj in police_objs:
				police_config_index = obj[0]
				police_parent_oid = obj[1]
				servicePolicyIndex = chopRight(chopLast(police_parent_oid, '.'), '.')
				class_map_object_index = obj[2]
				class_map_object_id = object_table.get('1.3.6.1.4.1.9.9.166.1.5.1.1.2.' + servicePolicyIndex + '.' + class_map_object_index, '')
				class_map_police_map[class_map_object_id] = police_config_index
			for r in res:
				#Now Looping on the walk.
				map_type = r[1].value
				#print map_type
				if map_type == '2':	#Only Class Mappings are used for configuration.
					servicePolicyIndex = r[0].oid.split('.')[-2]	#Policy Index
					#Now from the list filter out only the indexes which are required and also get the names of the indexes within the configuration.
					objIndex = r[0].oid.split('.')[-1]	#Object index 
					#Policy Index + Object Index is the oid Index used for polling
					oidIndex = servicePolicyIndex+'.'+objIndex	#Create the object index for polling
					#Class Map Configuration index 
					class_map_index = r[0].value
					#Gets the name of the class-map configuration
					#Policy Name = Cisco Policy Index name
					policy_id = object_table.get('1.3.6.1.4.1.9.9.166.1.5.1.1.2.' + servicePolicyIndex+'.'+servicePolicyIndex,'')
					#top_parent, parentn, parentn-1,... parent1,self 
					#print '\nservicePolicyIndex-->'servicePolicyIndex,'\n\n\n'
					#print '\nobjIndex-->'objIndex,'\n\n\n'
					parents_list = findParentObjectsList(object_table,servicePolicyIndex,objIndex) + [objIndex]
					#Get the Names String
					nameslist=[]
					parent_names = []
					names = []
					for parent in parents_list[:]:
						if safe_int(object_table.get('1.3.6.1.4.1.9.9.166.1.5.1.1.3.' + servicePolicyIndex+'.'+parent,'')) == 2 and objIndex != parent:
							nameslist.append(str(parent) + ':_' + str(object_names.get(servicePolicyIndex+'.'+parent)) + '_')
							parent_names.append("_" + re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$\-\(\)\]\[]','_',(str(object_names.get(servicePolicyIndex+'.'+parent)))) + "_")
							names.append(str(object_names.get(servicePolicyIndex+'.'+parent)))
						else:
							nameslist.append(str(parent) + ':' + str(object_names.get(servicePolicyIndex+'.'+parent)))
							parent_names.append(re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$\-\(\)\]\[]','_',(str(object_names.get(servicePolicyIndex+'.'+parent)))))
							names.append(str(object_names.get(servicePolicyIndex+'.'+parent)))
					mapping_entry = mapping_table.get(servicePolicyIndex,())
					policy_name = re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$\-]','_',nameslist[0].split(":")[-1])
					class_name = re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$\-]','_',nameslist[-1].split(":")[-1])
					policy_direction = iif(safe_int(mapping_entry[1]) == 1, 'In', 'Out')
					names.insert(-1, policy_direction)
					resource_object = {
						'ifIndex':mapping_entry[0],		  #Contains the interface for which this policy is applied
						'policy_direction':mapping_entry[1],	  #Contains the policy direction
						'policy_id':policy_id,
						'policy_name':policy_name,
						'policy_index':parents_list[0],
						'class_name':class_name,#This is the name of the index of the class object
						'class_id':class_map_index,		  #The last entry is the name of itself
						'oidIndex':oidIndex,			  #Oid index of the object
						'parents':re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$\-]','_','::'.join(nameslist)),
						'parent_names': parent_names,
						'resource_alias': string.join(names, ' - '),
						'interface_ip_addr': interface_index_ip_dict.get(mapping_entry[0], ''),
					}
					police_index = class_map_police_map.get(class_map_index)
					if police_index:
						police_params = police_info.get(police_index, {})
						if police_params:
							resource_object.update(police_params)
					resource_matrix[oidIndex] = resource_object
			for oidIndex, resource_object in resource_matrix.items():
					parent_names = resource_object.get('parent_names', [])
					del resource_object['parent_names']
					resource_alias = resource_object.get('resource_alias', '')
					del resource_object['resource_alias']
					interface_ip_addr = resource_object.get('interface_ip_addr', '')
					del resource_object['interface_ip_addr']
					interface_descr = get_interface_name(resource_object.get('ifIndex', ''), interfaceByIndex)
					interface_name = get_interface_name(resource_object.get('ifIndex', ''), interfaceNameByIndex)
					# res_description = '%s @@ %s' % (str(interface_name), interface_descr)
					res_description = self.if_index_map.get(str(resource_object.get('ifIndex')), {}).get('name', '')
					if not res_description:
						res_description = '%s @@ %s' % (str(interface_name), interface_descr)
					# For Class Path name
					policy_direction = get_direction(str(resource_object.get('policy_direction')))
					resource_paths = []
					resource_paths.append(interface_descr)
					resource_paths.append(policy_direction)
					resource_paths.extend(parent_names)
					resource_path = 'COS__dir__' + string.join(resource_paths, '__dir__')
					# For Class Map Parameters
					# resource_parameters = string.join(map(lambda a: '%s=%s' %(a), resource_object.items()), ',')
					params = {}
					params.update(resource_object)
					resource_params = {}
					resource_params['ip_addr'] = interface_ip_addr
					logScanMsg(2, 'Scanned Resource Matrix - %s' %(`resource_object`), self.module_name)
					# ret.append(LearnedResource(addr, community, resource_path, "CB QOS", "ciscocbcos.cfg", 
					# 			oid_index = resource_object.get("oidIndex",""), description=res_description, ip_addr=interface_ip_addr, resource_alias=resource_alias, params=parameters + resource_parameters))
					ret.append(LearnedResource(self.addr, resource_path, 'CB QOS', res_description, self.snmp_profile, 'ciscocbcos.cfg', 
						resource_alias=resource_alias, oid_index=resource_object.get("oidIndex",""), resource_params=resource_params, 
						poll_params=params
						))
			self.logMsg('Found %s CBQOS Policies'%len(ret))
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in COS Scanner - %s' %(msg), self.module_name)
		except:
			logScanExceptionMsg(4, 'Unknown Exception in COS Scanner', self.module_name)
		return ret

	def createSession(self):
		if scanner.snmpObj:
			scanner.snmpObj.close()
		scanner.snmpObj = None
		logScanMsg(2,"Close the existing session",self.module_name)
		self.initSNMP()
		logScanMsg(2,"Created the new session",self.module_name)

def getResultDictFromWalk(walkresult):#tested ok
	#print "\nwalkresult: ",walkresult,'\n\n'
	"""Build dictionary of the result objects and get the result
	"""
	result_dict = {}
	for objs in walkresult:
		for obj in objs:
			# oid = obj.oid.replace('.iso.org.dod.internet.private.enterprises','.1.3.6.1.4.1')
			result_dict.update({obj.oid:obj.value})
	#print '\n****return from getResultDictFromWalk:',result_dict
	return result_dict

def updateNamesForObjects(object_table,cbQosPolicyMapCfgDict,cbQosCMCfgDict):#tested ok
	"""Return a dictionary of oid indexed values policy"""
	name_dict = {}
	for obj in object_table:
		#update the service policy index from the list
		servicePolicyIndex = obj[0].oid.split('.')[-2]	#Policy Index
		objIndex = obj[0].oid.split('.')[-1]	#Object index 
		oidIndex = servicePolicyIndex+'.'+objIndex
		map_type = obj[1].value
		if safe_int(map_type) == 2:	#Class map object
			name_dict[oidIndex] = 	cbQosCMCfgDict.get('1.3.6.1.4.1.9.9.166.1.7.1.1.1.'+obj[0].value,'')	#update the name of the index entry
		elif safe_int(map_type) == 1:	#Policy Map Object 
			name_dict[oidIndex] = 	cbQosPolicyMapCfgDict.get('1.3.6.1.4.1.9.9.166.1.6.1.1.1.'+obj[0].value,'')	#update the name of the index entry
	#print '\n****return from updateNamesForObjects:',name_dict
	return name_dict

def findParentObjectsList(object_table,servicePolicyIndex,oidIndex):#tested ok
	#print '\nservicePolicyIndex-->',servicePolicyIndex,'\n\n\n'
	#print '\noidIndex-->',oidIndex,'\n\n\n'
	parentobj = object_table.get('1.3.6.1.4.1.9.9.166.1.5.1.1.4.'+servicePolicyIndex+'.'+oidIndex,'')
	#print "\n#########",parentobj
	if parentobj == '' or parentobj == '0' or parentobj == 0:
		return []
	obj = findParentObjectsList(object_table,servicePolicyIndex,parentobj)
	obj.append(parentobj)
	#print '\n****return from findParentObjectsList:',obj
	return obj

def get_direction(direction_index):
	"""
	Returns a String (direction name eg. Input) for an input of Index(eg. '1') 
	"""
	direction_map = {'1':'Input','2':'Output'}
	policy_direction = direction_map.get(direction_index,'ERROR: NO INTERFACE WITH SUCH INDEX')
	return policy_direction

def get_table_map(snmp_table_object):#tested ok
	table_map = map(lambda a: {"index":a[0].value, "oid":a[0].oid},snmp_table_object)
	return table_map

def get_interface_name(interface_index,interface_index_name_dict):#tested ok
	default_name = 'interface_%s' %interface_index
	return interface_index_name_dict.get(interface_index, default_name)

def interface_index_name_dict(if_descr_table_map):#tested ok
	logScanMsg(2, 'Interface Index Name Dict -- %s' %if_descr_table_map, 'Scanner')
	temp_dict = {}
	interface_count = len(if_descr_table_map)
	for i in range(0,interface_count):
		temp_dict.update({if_descr_table_map[i]["oid"].split(".")[-1]:if_descr_table_map[i]["index"]})
	logScanMsg(2, 'End of Interface Index Name Dict -- %s' %temp_dict, 'Scanner')
	return temp_dict
