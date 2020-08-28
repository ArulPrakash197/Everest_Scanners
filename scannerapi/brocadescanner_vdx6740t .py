######################################################################
###############do not change these following lines####################
from unmsutil import *
from scanner import LearnedResource, BaseScanner, logScanMsg, logScanExceptionMsg
######################################################################
######################################################################

def getEnterpriseID() :
	return "Brocade MIB", "enterprises.1588.3.3.1.137"

def getScanner() :
	return "Brocade MIB", "enterprises.1588.3.3.1.137", BrocadeScannerAPI()

class BrocadeScannerAPI(BaseScanner):

	def __init__(self):
		BaseScanner.__init__(self)
		self.device_profile = 'brocade_device.cfg'

	def getDeviceVendor(self):
		return 'Brocade'

	def getDeviceModel(self):
		return 'BR-VDX6740T'

	def getDeviceType(self) :
		return 'Switch'
		
	def getOSName(self) :
		return "Network OS"

	def getOSVersion(self):
		os_version = ''
		try:
			ins = self.multiSNMPGet('get', ['.1.3.6.1.4.1.1588.2.1.1.1.1.6.0'])
			os_version = ins[0].value
			if os_version in ["noSuchObject"]:
				ins = None
		except:
			ins = None
		# if ins :
		# 	self.logMsg(" found with first oid Obtained OS Version - %s" %ins)
		# 	os_version = ins[0].value
		# elif not ins:
		# 	try:
		# 		ins = self.multiSNMPGet('get', ['1.3.6.1.4.1.12356.101.4.1.1.0']) # mapOid Here 
		# 		os_version = ins[0].value
		# 	except:
		# 		ins = None
		# 		# pass
		self.logMsg("Obtained OS Version - %s" %os_version)
		return os_version

	def getDevicePollParams(self):
		params = {}
		try:
			ins = self.getSNMPTable(['.1.3.6.1.4.1.1588.2.1.1.1.26.1'])
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
		# For Power and Fan monitoring
		ret = []
		print "-----------enetering into scan others function "
		try:
			sensortypemap={1:'Temperature',2:'Fan',3:'Power'}
			self.logMsg("Scanning for Power and Fan")
			try:
				ins = self.getSNMPTable(['1.3.6.1.4.1.1588.2.1.1.1.1.22.1.2','1.3.6.1.4.1.1588.2.1.1.1.1.22.1.5'])
			except:
				ins = None
			if ins:
				#namestats='1.3.6.1.4.1.1588.2.1.1.1.1.22.1.3'
				
				for each_ins in ins:
					params={'fan':0,'power':0,'temp':0}
					sensortype = sensortypemap.get(safe_int(each_ins[0].value))
					print "_____________________________________ sensortype ___________",sensortype
					if sensortype=="Temperature":
						oid = each_ins[0].oid.split('.')[-1]
						params.update({'oidIndex': oid,'temp':1})
						value=each_ins[1].value
						ret.append(LearnedResource(self.addr, '%s' %value, '', 'Temperature_%s' %value, self.snmp_profile, 'brocadevdxtemperature.cfg',
						resource_alias=value, poll_params=params))
					elif sensortype=="Fan":
						oid = each_ins[0].oid.split('.')[-1]
						params.update({'oidIndex': oid,'fan':1})
						value=each_ins[1].value
						ret.append(LearnedResource(self.addr, '%s' %value, '', 'Fan_%s' %value, self.snmp_profile, 'brocadevdxtemperature.cfg',
						resource_alias=value, poll_params=params))
					else:
						oid = each_ins[0].oid.split('.')[-1]
						params.update({'oidIndex': oid,'power':1})
						value=each_ins[1].value
						ret.append(LearnedResource(self.addr, '%s' %value, '', 'Power_%s' %value, self.snmp_profile, 'brocadevdxtemperature.cfg',
						resource_alias=value, poll_params=params))

						
				
			
			
	
	 	except Exception, msg:
	 		logScanExceptionMsg(4, 'Exception in scanOthers - %s' %msg, self.module_name)
		return ret
