######################################################################
###############do not change these following lines####################
from unmsutil import *
from scanner import LearnedResource, BaseScanner, logScanMsg, logScanExceptionMsg
######################################################################
######################################################################
def getEnterpriseID() :
	return "Huawei Scanner Enterprise MIB", "enterprises.2011"

def getScanner() :
	return "Huawei Scanner Enterprise MIB", "enterprises.2011", HuaweiScannerAPI()

# scanner supported models: AR151, AR201, AR1220, AR2204, AR2220, AR2240
router_models = {'224.100':'AR 2220E','224.1': 'AR 1220', '224.5': 'AR 2220', '224.6': 'AR 2240', '224.9': 'AR 201', '224.27': 'AR 151', '224.48': 'AR 2204' , '2.9' : 'ne40E-X8' , '23.354' : 'S6720-54C-EI-48S-AC','2.235':'CH121'}
device_types = {'224.1': 'Router', '224.5': 'Router', '224.6': 'Router', '224.9': 'Router', '224.27': 'Router', '224.48': 'Router' , '2.9' : 'Router' , '23.354':'Router','2.235':'Server'}

class HuaweiScannerAPI(BaseScanner):

	def __init__(self):
		BaseScanner.__init__(self)
		self.device_profile = 'huaweiDevice.cfg'

	def getDeviceVendor(self):
		return 'Huawei'

	def checkForSerialNumber(self, serial_number, flag):
		""" Get Device Serial Number from Entity MIB.
		"""
		if serial_number:
			return serial_number
		self.logMsg('[Huawei] Scanning Device Serial Number, Flag %s' % flag)
		if not flag:
			try:
				# not a good way.. since there is no reference found to identify the component as chassis / frame, 
				# as the values are coming empty string.. so trying in worst possible way.
				# get first serial number in the table assuming that will be device serial number.
				serial_table = self.getSNMPTable([".1.3.6.1.2.1.47.1.1.1.1.11"])
				if serial_table:
					for ins in serial_table:
						if self.verifySNMPResponse(ins[0].value):
							serial_number = self.verifySNMPResponse(ins[0].value)
							break
					self.logMsg('[Huawei] Read Serial Number - %s for %s' %(serial_number, self.addr))
			except Exception, msg:
				logScanExceptionMsg(2, 'Exception while getting serial number from device [%s]: %s' %(self.addr, msg), self.module_name)
			self.logMsg('[Huawei] Get Serial Number Result - %s' % str(serial_number))
		return serial_number

	def getDeviceModel(self) :
		systemType = self.system_values.get('sysobjectid', '')
		sys_oid = string.join(systemType.split('.')[-2:], '.')

		model = router_models.get(sys_oid, '')
		return model

	def getDeviceType(self) :
		systemType = self.system_values.get('sysobjectid', '')
		sys_oid = string.join(systemType.split('.')[-2:], '.')
		device_type = device_types.get(sys_oid, 'Router')
		if device_type:
			return device_type
		return 'Router'

	def getOSName(self) :
		return "Huawei Versatile Routing Platform Software (VRP)"

	def getOSVersion(self):
		try:
			actual_descr = self.system_values.get('description', '')
			if not actual_descr :
				try:
					actual_descr = self.multiSNMPGet("get",["1.3.6.1.2.1.1.1.0"])[0]
				except:
					self.logMsg("Exception in getting thedevice description from the huawei scanner")
			os_ver = re.search(r'Version\s+(.*)\sCopy', actual_descr).groups()
			os_version = string.join(os_ver, ' ').strip()
			self.logMsg(" actual_descr %s ::  os_version %s"%(actual_descr,os_version))
		except:
			os_version = ''
		return os_version

	def getEnvironmentMonitoring(self):
		params = {}
		try:
			# check for Entity MIB to identify the corresponding component.
			# In Huawei for the models mentioned above, entity component name should be "SRU Board"
			self.logMsg("Scanning for Entity Mibs")
			if self.system_values.get('device_type') == 'OLT':
				self.device_profile = 'huawei_olt.cfg'
				return self.getOLTEnvironmentMonitoring()
			try:
				ins = self.getSNMPTable(['.1.3.6.1.2.1.47.1.1.1.1.2'])
			except:
				self.logMsg("Device doesn't support Entity MIB")
				ins = None
			if ins:
				entity_oid = ''
				for each_ins in ins:
					print "each_ins[0].value",each_ins[0].value
					#if str(each_ins[0].value).lower().startswith('sru board')!=-1:
					#	print "sru"
					#	entity_oid = each_ins[0].oid.split('.')[-1]
					#	break
					#checking whether its a CloudEngine 7800,CE7850-EI-B00,CE7850-32Q-EI Switch
					if str(each_ins[0].value).lower().find('cloudengine')!=-1:
						print "cloudengine"
						entity_oid = each_ins[0].oid.split('.')[-1]
						break
				print "***",entity_oid
				self.logMsg("Obtained Entity OID for SRU Board - %s"%entity_oid)
				if not entity_oid :
					# "Assembling Components,NetEngine9000,CR9PBKP08ADC,NE9000-8 Integrated Chassis DC Components"
					# if sru is not found then taking the first entity as entity description mentioned above .
					entity_oid = chopRight( ins[0][0].oid , '1.3.6.1.2.1.47.1.1.1.1.2.' )
					self.logMsg("Obtained Entity OID from top description is - %s %s "%(entity_oid,ins[0][0].value))
				if entity_oid:
					params['entityOid'] = entity_oid
					# check for CPU / Memory / Environment
					try:
						self.logMsg("Scanning for CPU / Memory / Environment Parameters")
						cpu_oid = '.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5.%s' %entity_oid
						memory_oid = '.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7.%s' %entity_oid
						memory_size_oid = '.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.9.%s' %entity_oid
						temperature_oid = '.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11.%s' %entity_oid
						voltage_oid = '.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.13.%s' %entity_oid
						ins = self.multiSNMPGet('get', [cpu_oid, memory_oid, memory_size_oid, temperature_oid, voltage_oid])
					except:
						self.logMsg("Device doesn't support Entity MIB")
						ins = None
					if ins:
						if len(ins) == 5:
							for each_ins in ins:
								if cpu_oid.endswith(each_ins.oid):
									params['cpu'] = 1
								elif memory_oid.endswith(each_ins.oid):
									params['memory'] = 1
								elif memory_size_oid.endswith(each_ins.oid):
									params['memory_size'] = each_ins.value
								elif temperature_oid.endswith(each_ins.oid):
									params['environment'] = 1

					if params:
						self.logMsg("Obtained OIDs for CPU / Memory / Environment Parameters - %s"%params)
				else:
					self.logMsg("Unable to get Entity OID")

				

		except Exception,msg :
			logScanExceptionMsg(4, "Exception in Getting Entity MIB Info for Huawei Scanner --- %s"%(msg), self.module_name)
			self.logMsg("Device doesn't support Entity MIB")
		except :
			logScanExceptionMsg(4, "Exception in Getting Entity MIB Info for Huawei Scanner", self.module_name)
			self.logMsg("Device doesn't support Entity MIB")
		return params

	def getOLTEnvironmentMonitoring(self):
		params = {}
		try:
			# check for Entity MIB to identify the corresponding component.
			# In Huawei for the models mentioned above, entity component name should be "SRU Board"
			self.logMsg("Scanning for OLT Entity Mibs")
			try:
				ins = self.getSNMPTable(['.1.3.6.1.2.1.47.1.1.1.1.2'])
			except:
				self.logMsg("Device doesn't support Entity MIB")
				ins = None
			if ins:
				entity_oid = ''
				control_board_oid = ''
				for each_ins in ins:
					if each_ins[0].value.lower().find('control unit board') != -1:
						control_board_oid = each_ins[0].oid.split('.')[-1]
						break
				if control_board_oid:
					self.logMsg("Obtained Control Board OID - %s"%control_board_oid)
					try:
						ins = self.multiSNMPGet('get', ['.1.3.6.1.2.1.47.1.1.1.1.7.%s' %control_board_oid])
					except:
						self.logMsg("Device doesn't support Entity MIB")
						ins = None
					if ins:
						control_board_name = ins[0].value
						try:
							eins = self.getSNMPTable(['.1.3.6.1.4.1.2011.2.6.7.1.1.2.1.7'])
						except:
							self.logMsg("Device doesn't support Entity MIB")
							eins = None
						if eins:
							for each_ins in eins:
								if each_ins[0].value == control_board_name:
									entity_oid = each_ins[0].oid[len('1.3.6.1.4.1.2011.2.6.7.1.1.2.1.7') + 1:]
									break
				else:
					self.logMsg("Unable to find Control Board OID")
				if entity_oid:
					self.logMsg("Obtained Entity OID for Control Board OID - %s"%entity_oid)
					params['entityOid'] = entity_oid
					# check for CPU / Memory / Environment
					try:
						self.logMsg("Scanning for CPU / Memory / Environment Parameters for OLT")
						cpu_oid = '.1.3.6.1.4.1.2011.2.6.7.1.1.2.1.5.%s' %entity_oid
						memory_oid = '.1.3.6.1.4.1.2011.2.6.7.1.1.2.1.6.%s' %entity_oid
						temperature_oid = '.1.3.6.1.4.1.2011.2.6.7.1.1.2.1.10.%s' %entity_oid
						ins = self.multiSNMPGet('get', [cpu_oid, memory_oid, temperature_oid])
					except:
						self.logMsg("Device doesn't support Entity MIB")
						ins = None
					if ins:
						if len(ins) == 3:
							for each_ins in ins:
								if cpu_oid.endswith(each_ins.oid):
									params['cpu'] = 1
								elif memory_oid.endswith(each_ins.oid):
									params['memory'] = 1
								elif temperature_oid.endswith(each_ins.oid):
									params['environment'] = 1
					if params:
						self.logMsg("Obtained OIDs for CPU / Memory / Environment Parameters - %s"%params)
				else:
					self.logMsg("Unable to get Entity OID")
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in Getting OLT Entity MIB Info for Huawei Scanner --- %s"%(msg), self.module_name)
			self.logMsg("Device doesn't support Entity MIB")
		except :
			logScanExceptionMsg(4, "Exception in Getting OLT Entity MIB Info for Huawei Scanner", self.module_name)
			self.logMsg("Device doesn't support Entity MIB")
		return params

	def getInterfacePollProfile(self, interface):
		""" Get Interface Poll Profile. mib2If / ifmib / stdIf / stdifmib / statusIf
		If interface supports
		high counter octets and errors, then ifmib.
		high counter octets and no errors, then stdifmib
		32 bit counter octets and errors, then mib2if
		32 bit counter octets and no errors, then stdif
		no counter octets and no errors, then statusif
		"""
		# 64 bit counters available
		hc_in_out_octets = ((interface.get('hc_in_octets') and interface.get('hc_in_octets') != '0') or (interface.get('hc_out_octets') and interface.get('hc_out_octets') != '0'))
		in_out_octets = ((interface.get('in_octets') and interface.get('in_octets') != '0') or (interface.get('out_octets') and interface.get('out_octets') != '0'))
		if (safe_int(interface.get('high_speed')) > 2 or safe_int(interface.get('if_speed')) > 2048000) and hc_in_out_octets:
			# physical interface
			if interface.get('in_errors') or interface.get('out_errors'):
				# use ifmib.
				interface['profile'] = 'ifmib.cfg'
			else:
				# sub interface. use stdifmib
				interface['profile'] = 'stdifmib.cfg'
		# 32 bit counters available
		elif in_out_octets:
			# physical interface
			if interface.get('in_errors') or interface.get('out_errors'):
				# use mib2If
				interface['profile'] = 'mib2If.cfg'
			else:
				# sub interface. use stdIf
				interface['profile'] = 'stdIf.cfg'
		# no traffic info available. use statusif
		else:
			interface['profile'] = 'statusIf.cfg'
		if interface.get('if_type') == 'GPON' and interface.get('actual_if_index') and safe_int(interface.get('actual_if_index')) < 0:
			interface['profile'] = 'huawei_gpon_if.cfg'

	def scanHost(self):
		ret = []
		return ret

	def scanOthers(self):
		ret = []
		try:
			if self.discovery_options.get('jitter'):
				ret += self.scanNQA()
				self.logMsg('Found %s NQA configurations'%len(ret))
			if self.discovery_options.get('qos'):
				cbqos = self.scanCBQoS()
				self.logMsg('Found %s CB QoS Policies'%len(cbqos))
				if cbqos:
					ret += cbqos
			ret += self.scanOpticalInterface()
			ret+=self.scaniBMC()
			ret+=self.scanstoragepool()
			ret+=self.scanFan()
			ret+=self.scanPower()
			self.logMsg('Scanning GPON Details')
			ret += self.scanGPON()
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanOthers of Huawei Scanner --- %s"%(msg), self.module_name)
		except :
			logScanExceptionMsg(4, "Exception in scanOthers of Huawei Scanner ", self.module_name)
		ret = filter(lambda a : a, ret)
		return ret

	def scanFan(self):
		ret = []
		try:
			self.logMsg("Scanning for Power and Fan")
			try:
				ins = self.getSNMPTable(['1.3.6.1.4.1.2011.5.25.31.1.1.10.1.7','1.3.6.1.4.1.2011.5.25.31.1.1.10.1.8'])
			except:
				ins = None
			if ins:
				for each_ins in ins:
					params={'fan':0,'power':0}
					oid = chopRight(each_ins[0].oid,"1.3.6.1.4.1.2011.5.25.31.1.1.10.1.7.")
					params.update({'oidIndex': oid,'fan':1})
					#print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",params
					value=each_ins[1].value
					ret.append(LearnedResource(self.addr, '%s' %value, '', 'Fan_%s' %value, self.snmp_profile, 'huawei_tempfan.cfg',
					resource_alias=value, poll_params=params))
					
		except Exception, msg:
	 		logScanExceptionMsg(4, 'Exception in scanOthers - %s' %msg, self.module_name)
		return ret

	def scanPower(self):
    		ret = []
		
    		try:
        		try:
            			ins = self.getSNMPTable(['.1.3.6.1.4.1.2011.5.25.31.1.1.18.1.6','.1.3.6.1.4.1.2011.5.25.31.1.1.18.1.9'])
        		except:
		        	ins = None
		        if ins:
		        	for each_ins in ins:
                			params={'fan':0,'power':0}
		                	oid = chopRight(each_ins[0].oid,"1.3.6.1.4.1.2011.5.25.31.1.1.18.1.6.")
                			params.update({'oidIndex': oid,'power':1})
							#print ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>",params
		                	value=each_ins[1].value
                			ret.append(LearnedResource(self.addr, '%s' %value, '', 'power_%s' %value, self.snmp_profile, 'huawei_tempfan.cfg',
		                	resource_alias=value, poll_params=params))
                
    		except Exception, msg:
        		logScanExceptionMsg(4, 'Exception in scanOthers - %s' %msg, self.module_name)
    		return ret

	def scanstoragepool(self):
		try:
			ret=[]
			poll_params=resource_params={}
			storage_mon=['.1.3.6.1.4.1.34774.4.1.23.4.2.1.2']
			_storage = self.getSNMPTable(storage_mon)
			if _storage:
				for each in _storage:
					storage_oid_index = chopRight(each[0].oid,"1.3.6.1.4.1.34774.4.1.23.4.2.1.2.")
					poll_params["storageoid"] = storage_oid_index					
					ret.append(LearnedResource(self.addr,"Pool Storage Monitoring", "Storage", "Storage", 
						self.snmp_profile,"huaweipoolstorage.cfg", active=1, oid_index=storage_oid_index, poll_params=poll_params))
				return ret
			else:
				return ret

		except Exception,msg:
			return ret
			logScanExceptionMsg(4, "Exception in scanOthers of Huawei Scanner --- %s"%(msg), self.module_name)

	def scaniBMC(self):
		try:
			ret=[]			
			#temperatureReading --> since temperature reading is not summarized ,showing individual temperature
			poll_params=resource_params={}
			temp_object = ['.1.3.6.1.4.1.2011.2.235.1.1.26.50.1.2']
			temp = self.getSNMPTable(temp_object)
			if temp :
				for temp_each in temp :
					temp_oid_index = chopRight(temp_each[0].oid,"1.3.6.1.4.1.2011.2.235.1.1.26.50.1.2.")
					poll_params["temp_oid"] = temp_oid_index
					temp_name=temp_each[0].value
					ret.append(LearnedResource(self.addr, "%s"%temp_name, "Device", "Device", 
						self.snmp_profile,"huaweiiBMCDevice.cfg", active=1, oid_index=temp_oid_index, poll_params=poll_params))

				return ret
			else:
				return ret
		except Exception,msg :
			logScanExceptionMsg(4, "Exception in scanOthers of Huawei Scanner --- %s"%(msg), self.module_name)
			return ret

	def scanOpticalInterface(self):
		try:
			logScanMsg(4, "Huawei scanOpticalInterface - OpticalInterface discovery - %s"%self.addr, self.module_name)
			self.logMsg('Scanning Optical Interfaces for Huawei')
			ret = []
			entity_oids = ['.1.3.6.1.2.1.47.1.1.1.1.7']
			entity_ret = self.getSNMPTable(entity_oids)
			oid_name_map = {}
			for et in entity_ret:
				eoid = et[0].oid.split('.')[-1]
				ename = et[0].value
				oid_name_map[safe_int(eoid)] = ename
			# print "\noid_name_map >> ",oid_name_map
			# EntityOpticalMode
			"""
			hwEntityOpticalMode OBJECT-TYPE	 
			-- 1.3.6.1.4.1.2011.5.25.31.1.1.3.1.1
				SYNTAX 	INTEGER  { 	 
					notSupported 	(1),	 
					singleMode 	(2),	 
					multiMode5 	(3),	 
					multiMode6 	(4),	 
					noValue 	(5)	 
				}
				MAX-ACCESS 	read-only 
			"""
			oid_optical_dict = {}
			optical_mode_oid = ['.1.3.6.1.4.1.2011.5.25.31.1.1.3.1.1']
			optical_ret = self.getSNMPTable(optical_mode_oid)
			for opt in optical_ret:
				if safe_int(opt[0].value) in (2, 3, 4):
					oid = safe_int(opt[0].oid.split('.')[-1])
					if oid in oid_name_map and oid_name_map.get(oid):
						oid_optical_dict[oid] = oid_name_map[oid].strip()
						# print "\noid_optical_dict[oid] >> ",oid_optical_dict[oid], oid
			for oid, interface_name in oid_optical_dict.iteritems():
				# add resource
				res_name = "OpticalInterfaces__dir__%s" % interface_name
				poll_params = {"interface_name":re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', interface_name), "device_type":"Huawei", "pollPeriod": 3600}
				poll_params['oidIndex'] = oid
				poll_params['poll_period'] = 3600
				ret.append(LearnedResource(self.addr, res_name, "Optical Interface", 'Optical Interface', self.snmp_profile, 'opticalinterface_huawei.cfg',active=1, poll_params=poll_params))
				logScanMsg(4, "Adding Huawei OpticalInterface  - %s  - %s"%(self.addr, res_name),self.module_name)
			return ret
		except Exception, msg:
			logScanExceptionMsg(4, "Exception in Huawei scanOpticalInterface OpticalInterface - %s %s"%(self.addr, msg), self.module_name)
			return []
		except:
			logScanExceptionMsg(4, "Unkown Exception in Huawei scanOpticalInterface OpticalInterface - %s"%(self.addr), self.module_name)
		return []


	def scanNQA(self):
		ret = []
		self.logMsg("Scanning for Huawei NQA Mibs")
		# scan NQA MIB (Network Quality Analysis) for Jitter Computation and following OIDs are used for Jitter Test calculation.
		# nqaScheduleOperStatus -> 1.3.6.1.4.1.2011.5.25.111.2.3.1.9 -> should be 4 (Active)
		# nqaAdminCtrlType -> 1.3.6.1.4.1.2011.5.25.111.2.1.1.4 -> Test type should be 5 for Jitter
		# nqaAdminCtrlTag -> 1.3.6.1.4.1.2011.5.25.111.2.1.1.3 -> NQA Description
		# nqaAdminCtrlFrequency -> 1.3.6.1.4.1.2011.5.25.111.2.1.1.5 -> Frequency
		# nqaAdminParaTargetAddress -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.2 -> Target Address
		# nqaAdminParaTargetPort -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.3 -> Target Port (Not Required for Jitter)
		# nqaAdminParaSourceAddress -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.5 -> Source Address
		# nqaAdminParaInterval -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.32 -> Inter Packet Delay between probe packets
		# nqaAdminParaNumPackets -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.33 -> No of Packets in each probe
		# nqaAdminParaProbeCount -> 1.3.6.1.4.1.2011.5.25.111.2.2.1.17 -> No of times probe repeated 
		oid_key_map = {
			'1.3.6.1.4.1.2011.5.25.111.2.1.1.3': 'test_description', 
			'1.3.6.1.4.1.2011.5.25.111.2.1.1.4': 'test_type', 
			'1.3.6.1.4.1.2011.5.25.111.2.1.1.5': 'frequency',
			'1.3.6.1.4.1.2011.5.25.111.2.3.1.9': 'test_status',
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.2': 'target_address', 
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.3': 'target_port', 
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.5': 'source_address', 
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.17': 'probe_count', 
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.32': 'inter_packet_delay', 
			'1.3.6.1.4.1.2011.5.25.111.2.2.1.33': 'no_of_packets',
			}
		oids = oid_key_map.keys()
		try:
			ins = self.getSNMPTable(oids)
		except:
			ins = None
			self.logMsg("Exception in scanning Huawei NQA MIBs")
		if ins:
			nqa_tests = []
			for each_ins in ins:
				nqa_test = {}
				for each_oid in each_ins:
					for oid in oids:
						if each_oid.oid.startswith(oid):
							nqa_test[oid_key_map.get(oid)] = each_oid.value
							nqa_test['nqa_oid'] = each_oid.oid.replace('%s.'%oid, '')
							break
				# test_status: 1: reset, 2: stop, 3: restart, 4: active, 5: inactive
				if safe_int(nqa_test.get('test_status')) == 4:
					nqa_tests.append(nqa_test)
			# supported test methods: ICMP ECHO & UDP Jitter
			test_profiles = {
					0: ('huaweiNQAICMP.cfg', 'ICMP Echo Test'), 5: ('huaweiNQAJitter.cfg', 'Jitter Test'), 6: ('huaweiNQAICMP.cfg', 'ICMP Echo Test')
				}
			self.logMsg(4, 'Found %s NQA Tests' %(len(nqa_tests)), self.module_name)
			if nqa_tests:
				for nqa_test in nqa_tests:
					try:
						test_type = safe_int(nqa_test.get('test_type'))
						if test_type in test_profiles:
							profile, test_descr = test_profiles.get(test_type)
							# self.logMsg('Test Description - %s and Test Type = %s' %(nqa_test.get('test_description', ''), test_descr))
							self.logMsg("Adding %s [%s] for Huawei" %(test_descr, test_type))
							source_address = nqa_test.get('source_address', '')
							target_address = nqa_test.get('target_address', '')
							target_port = nqa_test.get('target_port', '')
							inter_packet_delay = nqa_test.get('inter_packet_delay', '')
							frequency = nqa_test.get('frequency', '')
							test_description = re.sub('[\+\&\%\^\'\"\!\~\,\;\=\|\{\}\@\$]', '_', nqa_test.get('test_description', ''))
							params = {}
							params['oidIndex'] = nqa_test.get('nqa_oid', '')
							params['frequency'] = frequency
							params['interpacketinterval'] = inter_packet_delay
							resource_params = {}
							resource_params['sourceAddr'] = source_address
							resource_params['DestIp'] = target_address
							resource_params['targetPort'] = target_port
							resource_params['ip_addr'] = source_address
							res_name = '%s-%s-%s' %(source_address, target_address, test_description)
							ret.append(LearnedResource(self.addr, res_name, test_descr, nqa_test.get('test_description', ''), self.snmp_profile, profile,
									resource_alias=test_description, resource_params=resource_params, poll_params=params
									))
						else:
							self.logMsg('Unsupported Test type (%s) is found'%test_type)
					except Exception, msg:
						logScanExceptionMsg(4, 'Exception while adding resource for %s'%nqa_test, self.module_name)
		return ret

	def scanCBQoS(self):
		ret = []
		self.logMsg("Scanning for Huawei CB QOS MIB")
		try:
			# -----------------------------------------------------------------------------------------------------------------------------------------------
			# scan Huawei CB QOS MIB (Class based Quality of Service) for Traffic Violations.
			# -------------------------------------------------------------------------------
			# Interface Details:
			# ------------------
			# ifIndex -> 1.3.6.1.2.1.2.2.1.1 -> Interface Index
			# ifDescr -> 1.3.6.1.2.1.2.2.1.2 -> Interface Description
			# ifName -> 1.3.6.1.2.1.31.1.1.1.1 -> Interface Name
			# ifOperStatus -> 1.3.6.1.2.1.2.2.1.8 -> should be 1 (Up)
			# Class Map Details:
			# ------------------
			# hwCBQoSClassifierIndex -> 1.3.6.1.4.1.2011.5.25.32.1.1.1.2.1.1 -> Class Map Index
			# hwCBQoSClassifierName -> 1.3.6.1.4.1.2011.5.25.32.1.1.1.2.1.2 -> Class Map Name
			# Policy Details:
			# ---------------
			# hwCBQoSPolicyIndex -> 1.3.6.1.4.1.2011.5.25.32.1.1.3.2.1.1 -> Policy Index
			# hwCBQoSPolicyName -> 1.3.6.1.4.1.2011.5.25.32.1.1.3.2.1.2 -> Policy Name
			# Policy to Class Map:
			# --------------------
			# hwCBQoSPolicyClassClassifierName -> 1.3.6.1.4.1.2011.5.25.32.1.1.3.3.1.3 -> Policy to Class Map
			# 				Response: 1.3.6.1.4.1.2011.5.25.32.1.1.3.3.1.3.<policy index>.<class map index>: <class map name>
			# Interface to Policy Details:
			# ----------------------------
			# hwCBQoSIfApplyPolicyIfIndex -> 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.1 -> Interface to Policy Map Index
			# 				Response: 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.1.<if index>.<direction>: <if index>
			# hwCBQoSIfApplyPolicyDirection -> 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.2 -> Policy Direction
			# 				Response: 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.2.<if index>.<direction>: <policy direction>
			# hwCBQoSIfApplyPolicyName -> 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.3 -> Applied Policy Name
			# 				Response: 1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.3.<if index>.<direction>: <policy name>
			# Class Map to Police Configuration:
			# ----------------------------------
			# hwCBQoSClassifierName -> 1.3.6.1.4.1.2011.5.25.32.1.1.1.2.1.2 -> Class Map Name
			# hwCBQoSBehaviorName -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.2.1.2.<hwCBQoSBehaviorIndex>
			# 				Response: 1.3.6.1.4.1.2011.5.25.32.1.1.2.2.1.2.<hwCBQoSBehaviorIndex>: <class map name>
			# "hwCBQoSClassifierName == hwCBQoSBehaviorName" and get hwCBQoSBehaviorIndex
			# hwCBQoSCarCir -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.1.<hwCBQoSBehaviorIndex> -> CIR (Committed Information Rate - Kbps)
			# hwCBQoSCarCbs -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.2.<hwCBQoSBehaviorIndex> -> CBS (Committed Burst Size - bytes)
			# hwCBQoSCarEbs -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.3.<hwCBQoSBehaviorIndex> -> EBS (Excess Burst Size - bytes)
			# hwCBQoSCarPir -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.4.<hwCBQoSBehaviorIndex> -> PIR (Peak Information Rate - Kbps)
			# hwCBQoSCarPbs -> 1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.5.<hwCBQoSBehaviorIndex> -> PBS (Peak Burst Size - bytes)
			# 
			# Result:
			# -------
			# 	<Interface Descr> / <Policy Direction> / <Policy Name> / <Class Map Name>
			# Getting OID Index to poll (hwCBQoSIfVlanApplyPolicyVlanid1)
			# hwCBQoSIfVlanApplyPolicyVlanid1 is required for polling statistics from hwCBQoSPolicyStatClassifierTable.
			# However, hwCBQoSIfVlanApplyPolicyVlanid1 is not available in SNMP Walk. Hence do reverse computation
			# hwCBQoSPolicyStatClassifierName -> 1.3.6.1.4.1.2011.5.25.32.1.1.5.6.4.1.1 -> Class Map Name
			# 			Response: 1.3.6.1.4.1.2011.5.25.32.1.1.5.6.4.1.1.<if index>.<policy index>.<policy direction>.<vlanid index>.<ascii value of class name>
			# --------------------------------------------------------------------------------------------------------------------------------------------------
			ifIndex = '1.3.6.1.2.1.2.2.1.1'
			ifDescr = '1.3.6.1.2.1.2.2.1.2'
			ifName = '1.3.6.1.2.1.31.1.1.1.1'
			ipAdEntIfIndex = '1.3.6.1.2.1.4.20.1.2'
			ifOperStatus = '1.3.6.1.2.1.2.2.1.8'
			hwCBQoSClassifierIndex = '1.3.6.1.4.1.2011.5.25.32.1.1.1.2.1.1'
			hwCBQoSClassifierName = '1.3.6.1.4.1.2011.5.25.32.1.1.1.2.1.2'
			hwCBQoSPolicyIndex = '1.3.6.1.4.1.2011.5.25.32.1.1.3.2.1.1'
			hwCBQoSPolicyName = '1.3.6.1.4.1.2011.5.25.32.1.1.3.2.1.2'
			hwCBQoSPolicyClassClassifierName = '1.3.6.1.4.1.2011.5.25.32.1.1.3.3.1.3'
			hwCBQoSIfApplyPolicyIfIndex = '1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.1'
			hwCBQoSIfApplyPolicyDirection = '1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.2'
			hwCBQoSIfApplyPolicyName = '1.3.6.1.4.1.2011.5.25.32.1.1.4.1.1.3'
			hwCBQoSPolicyStatClassifierName = '1.3.6.1.4.1.2011.5.25.32.1.1.5.6.4.1.1'
			hwCBQoSBehaviorName = '1.3.6.1.4.1.2011.5.25.32.1.1.2.2.1.2'
			hwCBQoSBehaviorIndex = '1.3.6.1.4.1.2011.5.25.32.1.1.2.2.1.1'
			hwCBQoSCarCir = '1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.1'
			hwCBQoSCarCbs = '1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.2'
			hwCBQoSCarEbs = '1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.3'
			hwCBQoSCarPir = '1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.4'
			hwCBQoSCarPbs = '1.3.6.1.4.1.2011.5.25.32.1.1.2.3.1.5'
			try:
				interfaces = self.getSNMPTable([ifIndex, ifDescr, ifOperStatus, ifName])
			except:
				interfaces = []
			if interfaces:
				# filter the interfaces based on operation status 'Up'
				interface_map = dict(map(lambda a: (a[0], a[1]), filter(lambda a: int(a[2]) == 1, map(lambda a: (a[0].value, a[1].value, a[2].value), interfaces))))
				try:
					interface_name_map = dict(map(lambda a: (a[0], a[1]), filter(lambda a: int(a[2]) == 1, map(lambda a: (a[0].value, a[3].value, a[2].value), interfaces))))
				except:
					interface_name_map = {}
				logScanMsg(2, 'Interfaces with operational status - %s' %(`interface_map`), self.module_name)
				interface_index_ip_dict = {}
				try:
					if_index_ip_table = self.getSNMPTable([ipAdEntIfIndex])
				except:
					if_index_ip_table = []
				if if_index_ip_table:
					for ip_index in if_index_ip_table:
						oid = ip_index[0].oid
						if_index = ip_index[0].value
						ip_addr = oid[len(ipAdEntIfIndex)+1:]
						if if_index not in interface_index_ip_dict:
							interface_index_ip_dict[if_index] = []
						interface_index_ip_dict[if_index].append(ip_addr)
					for if_index in interface_index_ip_dict:
						ips = interface_index_ip_dict[if_index]
						interface_index_ip_dict[if_index] = string.join(ips, ';')
				logScanMsg(2, 'Scanned Interface Index and IP Addr Dict- %s' %(`interface_index_ip_dict`), self.module_name)
				# get Class Map Details
				try:
					class_map_list = self.getSNMPTable([hwCBQoSClassifierIndex, hwCBQoSClassifierName])
				except:
					class_map_list = []
				class_id_name_map = dict(map(lambda a: (a[0].value, a[1].value), class_map_list))
				class_name_id_map = dict(map(lambda a: (a[1].value, a[0].value), class_map_list))
				logScanMsg(2, 'Found - %s Class Maps' %(len(class_name_id_map)), self.module_name)
				# get Policy Details
				try:
					policy_list = self.getSNMPTable([hwCBQoSPolicyIndex, hwCBQoSPolicyName])
				except:
					policy_list = []
				policy_id_name_map = dict(map(lambda a: (a[0].value, a[1].value), policy_list))
				policy_name_id_map = dict(map(lambda a: (a[1].value, a[0].value), policy_list))
				logScanMsg(2, 'Found - %s Policies' %len(policy_name_id_map), self.module_name)
				# get Policy to Class Map Details
				try:
					policy_cm_list = self.getSNMPTable([hwCBQoSPolicyClassClassifierName])
				except:
					policy_cm_list = []
				policy_class_list = map(lambda a, b=hwCBQoSPolicyClassClassifierName: string.split(chopRight(a[0].oid, b)[1:], '.'), policy_cm_list)
				policy_class_map = {}
				# Mapping policy and class
				for policy in policy_class_list:
					if policy[0] not in policy_class_map:
						policy_class_map[policy[0]] = []
					policy_class_map[policy[0]].append(policy[1])
				logScanMsg(2, 'Policy to Class Map - %s' %`policy_class_map`, self.module_name)
				# get Interface to Policy Details
				try:
					if_policy_list = self.getSNMPTable([hwCBQoSIfApplyPolicyIfIndex, hwCBQoSIfApplyPolicyDirection, hwCBQoSIfApplyPolicyName])
				except:
					if_policy_list = []
				if_policy_details = map(lambda a: (a[0].value, (a[1].value, a[2].value)), if_policy_list)
				logScanMsg(2, 'Interface to Policy Details - %s' %`if_policy_details`, self.module_name)
				# mapping policies to interface. considering more than one policy per interface
				if_policy_map = {}
				for if_index, policy_details in if_policy_details:
					if if_index not in if_policy_map:
						if_policy_map[if_index] = []
					if_policy_map[if_index].append(policy_details)
				logScanMsg(2, 'Interface to Policy Map - %s' %`if_policy_map`, self.module_name)
				# Get police configuration for the class map
				class_map_police_map = {}
				try:
					behavior_table = self.getSNMPTable([hwCBQoSBehaviorIndex, hwCBQoSBehaviorName])
				except:
					behavior_table = []
				behavior_oid_name = {}
				map(lambda a, b=behavior_oid_name: b.update({a[1].value: a[0].value}), behavior_table)
				for behavior_name in behavior_oid_name:
					police_index = behavior_oid_name[behavior_name]
					if behavior_name in class_name_id_map:
						# class_map_index = class_name_id_map[behavior_name]
						class_map_police_map[behavior_name] = int(police_index)
				logScanMsg(2, 'Class Map to Police Index - %s' %`class_map_police_map`, self.module_name)
				try:
					police_info_table = self.getSNMPTable([hwCBQoSCarCir, hwCBQoSCarCbs, hwCBQoSCarEbs, hwCBQoSCarPir, hwCBQoSCarPbs])
				except:
					police_info_table = []
				police_info = {}
				# helper function to format the value
				def checkValue(value, factor=None):
					if (int(value) == (int(math.pow(2, 32)) - 1)):
						return -1
					if factor:
						return int(value) * factor
					return int(value)
				# helper function to format the value ends here
				for police in police_info_table:
					behavior_index = int(chopRight(police[0].oid, '.'))
					police_info[behavior_index] = {}
					police_info[behavior_index]['cir'] = checkValue(police[0].value, 1000)
					police_info[behavior_index]['cbs'] = checkValue(police[1].value)
					police_info[behavior_index]['ebs'] = checkValue(police[2].value)
					police_info[behavior_index]['pir'] = checkValue(police[3].value, 1000)
					police_info[behavior_index]['pbs'] = checkValue(police[4].value)
				logScanMsg(2, 'Police Info - %s' %`police_info`, self.module_name)
				try:
					stat_table = self.getSNMPTable([hwCBQoSPolicyStatClassifierName])
				except:
					stat_table = []
				# Getting <if index>.<policy index>.<policy direction>.<vlanid index>.<ascii value of class name>. 
				# Sine vlanid index is not available in SNMP Walk, match the remaining parameters. 
				if_policy_cos_map_oid = {}
				for stat in stat_table:
					oid = stat[0].oid
					class_name = stat[0].value
					cos_name_index = '.'.join(map(lambda a: str(ord(a)), class_name))
					oid_index = oid[len(hwCBQoSPolicyStatClassifierName)+1:]
					map_oid = oid_index[:-1*(1+len(cos_name_index))]
					m_oid_list = map_oid.split('.')
					if_index = m_oid_list[0]
					policy_id = m_oid_list[1]
					direction = m_oid_list[2]
					if_policy_cos_map_oid[(if_index, direction, policy_id, cos_name_index)] = oid_index
				direction_map = {'1': 'Input', '2': 'Output'}
				for if_index in interface_map:
					try:
						if if_index in if_policy_map:
							interface_descr = interface_map.get(if_index, '')
							interface_ip_addr = interface_index_ip_dict.get(if_index, '')
							interface_name = interface_name_map.get(if_index, '')
							res_description = '%s @@ %s'%(interface_name, interface_descr)
							# Get applied policies of that interface
							policies = if_policy_map[if_index]
							for policy in policies:
								try:
									policy_direction, applied_policy = policy
									policy_id = policy_name_id_map[applied_policy]
									# Get all the class maps of that applied policy
									class_maps = policy_class_map[policy_id]
									for class_map in class_maps:
										cos_params = {
											'ifIndex': if_index,
											'policy_id': policy_id,
											'policy_name': applied_policy,
											'policy_direction': policy_direction,
										}
										class_map_name = class_id_name_map[class_map]
										cos_params['class_name'] = class_map_name
										police_index = class_map_police_map.get(class_map_name)
										if police_index:
											behavior_params = police_info.get(police_index, {})
											if behavior_params:
												cos_params.update(behavior_params)
										cos_params['class_id'] = class_map
										cos_name_index = '.'.join(map(lambda a: str(ord(a)), class_map_name))
										# Get the oidindex using reverse map by matching 4 parameters.
										oidIndex = if_policy_cos_map_oid.get((if_index, policy_direction, policy_id, cos_name_index), '')
										policy_direction_map = {'1': 'In', '2': 'Out'}
										if oidIndex:
											cos_params['oidIndex'] = oidIndex
											resource_alias = '%s - %s - %s' %(applied_policy, policy_direction_map[policy_direction], class_map_name)
											# resource_parameters = string.join(map(lambda a: '%s=%s' %(a), cos_params.items()), ',')
											# construct the path structure COS/<Interface>/<Direction>/<Policy>/<ClassMap>
											resource_path = 'COS__dir__%s__dir__%s__dir__%s__dir__%s' %(interface_descr, direction_map[policy_direction], applied_policy, class_map_name)
											resource_params = {}
											resource_params['ip_addr'] = interface_ip_addr
											logScanMsg(2, 'Constructed COS Profile - %s' %`resource_path`, self.module_name)
											ret.append(LearnedResource(self.addr, resource_path, 'CB QOS', res_description, self.snmp_profile, 'huaweicbqos.cfg',
												resource_alias=resource_alias, oid_index=oidIndex, resource_params=resource_params, poll_params=cos_params))
											# ret.append(LearnedResource(addr, community, resource_path, "CB QOS", "huaweicbqos.cfg", 
											# 			oid_index = oidIndex, description=res_description, ip_addr=interface_ip_addr, resource_alias=resource_alias, params=parameters + resource_parameters))
								except Exception, msg:
									logScanExceptionMsg(4, 'Exception in mapping policies - %s' %(msg), self.module_name)
					except Exception, msg:
						logScanExceptionMsg(4, 'Exception in forming resource - %s' %(msg), self.module_name)
					except:
						logScanExceptionMsg(4, 'Unknown Exception in forming resource', self.module_name)
			self.logMsg('Found %s CBQOS Policies'%len(ret))
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in Huawei CBQOS Scan - %s' %(msg), self.module_name)
		except:
			logScanExceptionMsg(4, 'Unknown Exception in Huawei CBQOS Scan', self.module_name)
		return ret

	def scanGPON(self):
		ret = []
		ifType = "1.3.6.1.2.1.2.2.1.3"
		ifName = "1.3.6.1.2.1.31.1.1.1.1"
		try:
			try:
				interfaces = self.getSNMPTable([ifType, ifName])
			except:
				interfaces = []
			gpon_interfaces = []
			for interface in interfaces:
				if_type = interface[0].value
				if_name = interface[1].value
				# gpon
				if int(self.verifySNMPResponse(if_type)) == 250:
					if_index = chopRight(interface[0].oid, '.')
					gpon_interfaces.append((if_index, if_name))
			# proceed the scanning if GPON interfaces found
			if gpon_interfaces:
				self.logMsg('Found %s GPON Interfaces' %len(gpon_interfaces))
				for if_index, if_name in gpon_interfaces:
					ont_address = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.9.%s" %if_index
					ont_serials = "1.3.6.1.4.1.2011.6.128.1.1.2.43.1.3.%s" %if_index
					ont_models = "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.4.%s" %if_index
					ont_hardware_version = "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.1.%s" %if_index
					ont_software_version = "1.3.6.1.4.1.2011.6.128.1.1.2.45.1.5.%s" %if_index
					olt_ont_distance = "1.3.6.1.4.1.2011.6.128.1.1.2.46.1.20.%s" %if_index
					ont_map = {}
					try:
						ont_address_table = self.getSNMPTable([ont_address])
					except:
						ont_address_table = []
					logScanMsg(4, '%s ONTs are connected with - %s' %(len(ont_address_table), if_name), self.module_name)
					if ont_address_table:
						for ont in ont_address_table:
							ont_index = ont[0].oid[len(ont_address)+1:]
							ont_map[ont_index] = {'ont_address': ont[0].value}
					try:
						ont_serials_table = self.getSNMPTable([ont_serials])
					except:
						ont_serials_table = []
					if ont_serials_table:
						for ont in ont_serials_table:
							ont_index = ont[0].oid[len(ont_serials)+1:]
							if ont_index in ont_map:
								ont_map[ont_index].update({'serial_number': ont[0].value})
					try:
						ont_hw_ver_table = self.getSNMPTable([ont_hardware_version, ont_software_version])
					except:
						ont_hw_ver_table = []
					if ont_hw_ver_table:
						for ont in ont_hw_ver_table:
							ont_index = ont[0].oid[len(ont_hardware_version)+1:]
							if ont_index in ont_map:
								ont_map[ont_index].update({'os_version': '%s [%s]' %(ont[0].value, ont[1].value)})
					try:
						ont_models_table = self.getSNMPTable([ont_models])
					except:
						ont_models_table = []
					if ont_models_table:
						for ont in ont_models_table:
							ont_index = ont[0].oid[len(ont_models)+1:]
							if ont_index in ont_map:
								ont_map[ont_index].update({'model': ont[0].value})
					try:
						olt_ont_distance_table = self.getSNMPTable([olt_ont_distance])
					except:
						olt_ont_distance_table = []
					if olt_ont_distance_table:
						for ont in olt_ont_distance_table:
							ont_index = ont[0].oid[len(olt_ont_distance)+1:]
							if ont_index in ont_map:
								# ont_map[ont_index].update({'distance': '%.3f' %(safe_float(ont[0].value)/1000)})
								ont_map[ont_index].update({'distance': ont[0].value})
					logScanMsg(4, 'ont_map - %s' %ont_map, self.module_name)
					for ont_index in ont_map:
						ont_obj = ont_map[ont_index]
						ont_obj['make'] = 'Huawei'
						ont_obj['device_type'] = 'ONT'
						ont_obj['os_name'] = 'Huawei ONT OS'
						ont_obj['descr'] = ont_obj.get('ont_address', '')
						ont_obj['if_name'] = if_name
						ont_obj['if_index'] = if_index
						ont_obj['topo_obj'] = {}
						ont_obj['topo_obj']['source_node'] = self.addr
						ont_obj['topo_obj']['source_res'] = if_name
						ont_obj['topo_obj']['target_node'] = ont_obj.get('ont_address', '')
						ont_obj['topo_obj']['target_res'] = '%s/%s:%s' %(self.addr, if_name, ont_obj.get('ont_address', ''))
						ont_obj['topo_obj']['name'] = '%s/%s:%s' %(self.addr, if_name, ont_obj.get('ont_address', ''))
						ont_obj['topo_obj']['descr'] = 'GPON: OLT-ONT'
						ont_obj['topo_obj']['rel_type'] = 1
						ont_obj['topo_obj']['conn_type'] = 'GPON: OLT-ONT'
						ont_obj['topo_obj']['distance'] = safe_int(ont_obj.get('distance', ''))
						ont_obj['topo_obj']['show_on_flatview'] = 1
						oid_index = '%s.%s' % (if_index, ont_index)
						ont_obj['poll_addr'] = 'ONT:%s' %(ont_obj.get('ont_address', ''))
						ont_obj['hostname'] = ont_obj.get('ont_address', '')
						ont_obj['dest_addr'] = self.addr
						ret.append(LearnedResource(self.addr, '%s/%s:%s' %(self.addr, if_name, ont_obj.get('ont_address', '')), 'ONT', ont_obj.get('ont_address', ''), 
                                                    self.snmp_profile, 'huawei_ont.cfg', resource_alias=ont_obj.get('ont_address', ''), oid_index=oid_index, resource_params=ont_obj, node_obj=ont_obj))
			else:
				self.logMsg('GPON Interfaces Not Found')
		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in Huawei GPON Scan - %s' %(msg), self.module_name)
		except:
			logScanExceptionMsg(4, 'Unknown Exception in Huawei GPON Scan', self.module_name)
		return ret

"""
.1.3.6.1.2.1.47.1.1.1.1.7 provides names for hwEntityId
.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11 temperature sensors
.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.12 temperature sensors high threshold
.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.16 temperature sensors low threshold
.1.3.6.1.4.1.2011.5.25.31.1.1.1.1.22 transceiver optical power rx (NE40E)
.1.3.6.1.4.1.2011.5.25.31.1.1.3.1.8 transceiver optical power rx (switches)
"""
