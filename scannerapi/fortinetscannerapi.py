######################################################################
###############do not change these following lines####################
from unmsutil import *
from scanner import LearnedResource, BaseScanner, logScanMsg, logScanExceptionMsg
######################################################################
######################################################################
#This scanner will support all the models which are mentioned in {device_models_type} and all the enterprise oid ending with keys in {device_models}.
######################################################################
#Note -VM64 is not counted in device_models_type

def getEnterpriseID() :
	return "Fortinet MIB", "enterprises.12356.101.1"

def getScanner() :
	return "Fortinet MIB", "enterprises.12356.101.1", FortinetScannerAPI()

device_models_type={'304':[('FG-30D','')],
'305':[('FG-30D-POE','')],
'306':[('FG-30E','')],
'307':[('FGR-30D','Fortigate Rugged')],
'308':[('FGR-35D','Fortigate Rugged')],
'309':[('FR-30DA','Firewall')],
'314':[('FWF-30D','Fortigate WIFI')],
'315':[('FWF-30D-POE','Fortigate WIFI')],
'316':[('FWF-30E','Fortigate WIFI')],
'320':[('FG-30EN','')],
'321':[('FG-30EI','')],
'322':[('FW-30EN','Firewall')],
'323':[('FW-30EI','Firewall')],
'505':[('FG-50E','')],
'506':[('FWF-50E','Fortigate WIFI')],
'515':[('FG-51E','')],
'516':[('FWF-51E','Fortigate WIFI')],
'517':[('FW-502R','Firewall')],
'518':[('FG-52E','')],
'624':[('FG-60D','')],
'625':[('FG-60D-POE','')],
'626':[('FWF-60D','Fortigate WIFI')],
'627':[('FW-60DP','Firewall')],
'630':[('FG-90D','')],
'631':[('FG-90D-POE','')],
'632':[('FWF-90D','Fortigate WIFI')],
'633':[('FWF-90D-POE','Fortigate WIFI')],
'634':[('FG-94D-POE','')],
'635':[('FG-98D-POE','')],
'636':[('FG-92D','')],
'637':[('FWF-92D','Fortigate WIFI')],
'638':[('FGR-90D','')],
'639':[('FWF-60E','Fortigate WIFI')],
'640':[('FG-61E','')],
'641':[('FG-60E','')],
'642':[('FG-60E-POE','')],
'643':[('FGR-60D','')],
'649':[('FWF-61E','Fortigate WIFI')],
'661':[('FG-60EJ','')],
'662':[('FWF-60EJ','Fortigate WIFI')],
'663':[('FG-60EV','')],
'664':[('FWF-60EV','Fortigate WIFI')],
'700':[('FG-70D','')],
'701':[('FG-70D-POE','')],
'803':[('FG-80D','')],
'841':[('FG-80D-POE','')],
'842':[('FG-80E','')],
'843':[('FG-81E','')],
'844':[('FG-81E-POE','')],
'900':[('FG-900D','')],
'940':[('FG-90E','')],
'941':[('FG-91E','')],
'1004':[('FG-100D','')],
'1005':[('FG-140E','')],
'1006':[('FG-140EP','')],
'1041':[('FG-100E','')],
'1042':[('FG-100EF','')],
'1043':[('FG-101E','')],
'1401':[('FG-140D','')],
'1402':[('FG-140P','')],
'2005':[('FG-200D','')],
'2006':[('FG-240D','')],
'2007':[('FG-200DP','')],
'2008':[('FG-240DP','')],
'2009':[('FG-200E','')],
'2010':[('FG-201E','')],
'2013':[('FG-280D','')],
'3006':[('FG-3HD','')],
'3007':[('FG-300E','')],
'3008':[('FG-301E','')],
'4004':[('FG-400D','')],
'4007':[('FG-400E','')],
'4008':[('FG-401E','')],
'5004':[('FG-400E','')],
'5005':[('FG-500E','')],
'5006':[('FG-501E','')],
'6004':[('FG-600D','')],
'6005':[('FG-600E','')],
'6006':[('FG-500E','')],
'8004':[('FG-800D','')],
'10005':[('FG-1000D','')],
'12000':[('FG-1200D','')],
'15000':[('FG-1500D','')],
'15001':[('FG-1500DT','')],
'20000':[('FG-2000E','')],
'25000':[('FG-2500E','')],
'30000':[('FG-3000D','')],
'31000':[('FG-3100D','')],
'32000':[('FG-3200D','')],
'37000':[('FG-3700D','')],
'38000':[('FG-3800D','')],
'38101':[('FG-3810D','')],
'38150':[('FG-3815D','')],
'39601':[('FG-3960E','')],
'39801':[('FG-3980E','')],
'50015':[('FG-5001D','')],
'50016':[('FG-5001E','')],
'50017':[('FG-5001E1','')],
}



class FortinetScannerAPI(BaseScanner):

	def __init__(self):
		BaseScanner.__init__(self)
		self.device_profile = 'fortinet.cfg'

	def getDeviceVendor(self):
		return 'Fortinet'

	def getDeviceModel(self):
		try:
			systemType = self.system_values.get('sysobjectid', '')
			sys_oid = string.join(systemType.split('.')[-1:], '.')
			model = device_models_type.get(sys_oid, '')[0][0]
			if not model:
				return 'Fortinet'
			return model
		except:
			return 'Fortinet'

	def getDeviceType(self) :
		try:
			systemType = self.system_values.get('sysobjectid', '')
			sys_oid = string.join(systemType.split('.')[-1:], '.')
			device_type = device_models_type.get(sys_oid, '')[0][1]
			if not device_type:
				return 'Firewall'
			return device_type
		except:
			return 'Firewall'
		
	def getOSName(self) :
		return "FortiOS"

	def getOSVersion(self):
		os_version = ''
		try:
			ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.12356.1.1.2.0'])
			os_version = ins[0].value
			if os_version in ["noSuchObject"]:
				ins = None
		except:
			ins = None
		if ins :
			self.logMsg(" found with first oid Obtained OS Version - %s" %ins)
			os_version = ins[0].value
		elif not ins:
			try:
				ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.12356.101.4.1.1.0']) # mapOid Here 
				os_version = ins[0].value
			except:
				ins = None
				# pass
		self.logMsg("Obtained OS Version - %s" %os_version)
		return os_version

	def getDevicePollParams(self):
		params = {}
		try:
			ins = self.getSNMPTable(['1.3.6.1.4.1.12356.1.1.6.5'])
		except:
			ins = None
		if ins:
			try:
				oid = "." + string.join(map(lambda a: str(a), ins[0][0].oidlist()),".")
				oidIndex = chopRight(oid,oid_query)
				params["oidIndex"] = oidIndex
			except:
				oid = safe_int(ins[0][0].oid[-1:])
				params["oidIndex"] = oid
		return params
		


	def scanOthers(self):
		params = {}
		ret = []
		try:
			self.logMsg("Scanning for Fortinet System Parameters")
			sys_oid = ".1.3.6.1.4.1.12356.101.3.1"
			try:
				ins = self.getSNMPTable([sys_oid])
			except:
				ins = None
			self.logMsg("Scanning for Fortinet System Parameters, ins: %s"%ins)
			if ins:
				ret.append(LearnedResource(self.addr , "Fortinet" ,"Fortinet System" ,"Fortinet Firewall System" , self.snmp_profile ,"fortinet_sys.cfg" ))
			
			self.logMsg("Scanning for Fortinet VDoms Parameters")
			vdom_oid = '.1.3.6.1.4.1.12356.101.3.2.1.1.2'
			ins = self.getSNMPTable([vdom_oid])
			self.logMsg("Scanning for Fortinet VDoms Parameters, ins: %s"%ins)
			if ins:
				for each_ins in ins:
					oid = each_ins[0].oid.split('.')[-1]
					value = each_ins[0].value
					params = {'oidIndex': oid}
					ret.append(LearnedResource(self.addr, "Fortinet: %s"%value, "Fortinet VDoms", "Fortinet Firewall VDoms", 
						self.snmp_profile, 'fortinet_vdoms.cfg', active=1, oid_index=oid, poll_params=params))


			
			self.logMsg("Scanning for Fortinet CPU core")
			ins = self.getSNMPTable(['.1.3.6.1.4.1.12356.101.4.4.2.1.1','.1.3.6.1.4.1.12356.101.4.4.2.1.2'])
			self.logMsg("Scanning for Fortinet Parameters, ins: %s"%ins)
			if ins:
				for each_ins in ins:
					params = {'cpu':0,'fan':0,'temp':0,'vout':0}
					oid = each_ins[1].oid.split('.')[-1]
					value = each_ins[0].value
					params.update({'oidIndex': oid,'cpu':1})
					ret.append(LearnedResource(self.addr, "CPU Core %s"%value, "CPU Core", "Fortinet Firewall CPU", 
						self.snmp_profile, 'fortinet_param.cfg', active=1, oid_index=oid, poll_params=params))


			self.logMsg("Scanning for Fortinet Parameters")
			ins = self.getSNMPTable(['.1.3.6.1.4.1.12356.101.4.3.2.1.2','.1.3.6.1.4.1.12356.101.4.3.2.1.3'])
			self.logMsg("Scanning for Fortinet Parameters, ins: %s"%ins)
			if ins:
				for each_ins in ins:
					params = {'cpu':0,'fan':0,'temp':0,'vout':0}
					if str(each_ins[0].value).lower().find('temp')!=-1:
						oid = each_ins[1].oid.split('.')[-1]
						value = each_ins[0].value
						params.update({'oidIndex': oid,'temp':1})
						ret.append(LearnedResource(self.addr, "Fortinet: %s"%value, "Temperature", "Fortinet Firewall Temperature", 
							self.snmp_profile, 'fortinet_param.cfg', active=1, oid_index=oid, poll_params=params))
					if str(each_ins[0].value).lower().find('fan')!=-1:
						oid = each_ins[1].oid.split('.')[-1]
						value = each_ins[0].value
						params.update({'oidIndex': oid,'fan':1})
						ret.append(LearnedResource(self.addr, "Fortinet: %s"%value, "Fan", "Fortinet Firewall Fan", 
							self.snmp_profile, 'fortinet_param.cfg', active=1, oid_index=oid, poll_params=params))

					if str(each_ins[0].value).lower().find('vout')!=-1:
						oid = each_ins[1].oid.split('.')[-1]
						value = each_ins[0].value
						params.update({'oidIndex': oid,'vout':1})
						ret.append(LearnedResource(self.addr, "Fortinet: %s"%value, "Voltage", "Fortinet Firewall Voltage", 
							self.snmp_profile, 'fortinet_param.cfg', active=1, oid_index=oid, poll_params=params))

		except Exception, msg:
			logScanExceptionMsg(4, 'Exception in scanOthers - %s' %msg, self.module_name)
		return ret
