
import datetime

from badauth.protocols.kerberos import logger
from badauth.common.winapi.constants import ISC_REQ
from badauth.common.credentials.kerberos import KerberosCredential
from badauth.protocols.kerberos.gssapi import get_gssapi, KRB5_MECH_INDEP_TOKEN
from badauth.protocols.kerberos.gssapismb import get_gssapi as gssapi_smb

from kerbad.common.spn import KerberosSPN
from kerbad.gssapi.gssapi import GSSAPIFlags
from kerbad.protocol.asn1_structs import AP_REP, EncAPRepPart, Ticket, EncryptedData
from kerbad.protocol.constants import MESSAGE_TYPE
from kerbad.protocol.ticketutils import construct_apreq_from_ticket
from kerbad.protocol.encryption import Key, _enctype_table
from kerbad.aioclient import AIOKerberosClient
from kerbad.protocol.errors import KerberosError, KerberosErrorCode


class KerberosClientNative:
	def __init__(self, credential:KerberosCredential):
		self.credential = credential
		self.ccred = self.credential.to_ccred()
		
		self.kc = None
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.seq_number = 0
		self.from_ccache = False
	
		self.flags = \
			GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		
	
	def get_seq_number(self):
		"""
		Returns the initial sequence number. It is 0 by default, but can be adjusted during authentication, 
		by passing the 'seq_number' parameter in the 'authenticate' function
		"""
		return self.seq_number
	
	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return GSSAPIFlags.GSS_C_INTEG_FLAG in self.flags
	
	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return GSSAPIFlags.GSS_C_CONF_FLAG in self.flags
				
	async def sign(self, data:bytes, message_no:int, direction = 'init', reset_cipher = False):
		"""
		Signs a message.

		The ``reset_cipher`` keyword is accepted (and ignored) for parity with
		the NTLM sign() signature so that SPNEGO/DCE-RPC callers that pass it
		uniformly do not blow up when the selected GSS context is Kerberos.
		Kerberos GSS_GetMIC is stateless wrt cipher reset, so this is a no-op.
		"""
		del reset_cipher  # no-op for Kerberos GSS_GetMIC; kept for SPNEGO parity
		return self.gssapi.GSS_GetMIC(data, message_no, direction = direction)
		
	async def encrypt(self, data:bytes, message_no:int, *args, **kwargs):
		"""
		Encrypts a message. 
		"""
		data, eeee  = self.gssapi.GSS_Wrap(data, message_no, *args, **kwargs)
		return data, eeee 
		
	async def decrypt(self, data:bytes, message_no:int, *args, **kwargs):
		"""
		Decrypts message. Also performs integrity checking.
		"""

		return self.gssapi.GSS_Unwrap(data, message_no, *args, **kwargs)
	
	def get_session_key(self):
		return self.session_key.contents

	def iscreq_to_gssapiflags(self, flags:ISC_REQ):
		if flags is None:
			return self.flags
		kflags = GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.INTEGRITY in flags:
			kflags |= GSSAPIFlags.GSS_C_INTEG_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_INTEG_FLAG
		if ISC_REQ.CONFIDENTIALITY in flags:
			kflags |= GSSAPIFlags.GSS_C_CONF_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_CONF_FLAG
		if ISC_REQ.REPLAY_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_REPLAY_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_REPLAY_FLAG
		if ISC_REQ.SEQUENCE_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.USE_DCE_STYLE in flags:
			kflags |= GSSAPIFlags.GSS_C_DCE_STYLE
		else:
			kflags &= ~GSSAPIFlags.GSS_C_DCE_STYLE
		if ISC_REQ.MUTUAL_AUTH in flags:
			kflags |= GSSAPIFlags.GSS_C_MUTUAL_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_MUTUAL_FLAG
		return kflags
		
	
	async def authenticate(self, authData:bytes, flags:ISC_REQ = None, seq_number:int = 0, cb_data:bytes = None, spn:str = None, **kwargs):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		try:
			self.flags = self.iscreq_to_gssapiflags(flags)
			logger.debug('Flags: %s' % self.flags)
			

			if spn is None:
				raise Exception("SPN is needed for kerberos!")
			else:
				spn = KerberosSPN.from_spn(spn)

			logger.debug('SPN: %s' % spn)
			if self.kc is None:
				self.kc = AIOKerberosClient(self.ccred, self.credential.target)

			if self.iterations == 0:
				self.seq_number = 0
				self.iterations += 1
				
				try:
					#check TGS first, maybe ccache already has what we need
					for target in self.ccred.ccache.list_targets():
						# just printing this to debug...
						logger.debug('CCACHE SPN record: %s' % target)
					tgs, encpart, self.session_key, err = self.kc.tgs_from_ccache(spn)
					if err:
						raise err
					logger.debug('Got TGS from CCACHE!')
					
					self.from_ccache = True
				except:
					# fetching TGT
					try:
						tgt = await self.kc.with_clock_skew(self.kc.get_TGT, override_etype = self.credential.etypes)
					except KerberosError as e:
						if e.errorcode == KerberosErrorCode.KDC_ERR_WRONG_REALM:
							# if the target user is in a different domain, we need to get a referral ticket
							# however at this point it's a guess work, as this heavily relies on the target domain's trust settings
							# and the correct DNS settings

							newtarget = self.kc.target.get_kerberos_target(dc_ip=self.kc.credential.domain, domain=self.kc.credential.domain)
							newkc = AIOKerberosClient(self.ccred, newtarget)
							ref_tgs, ref_encpart, ref_key, new_factory = await newkc.with_clock_skew(newkc.get_referral_ticket, spn.domain, self.credential.target.get_ip_or_hostname())
							self.kc = new_factory.get_client()
							tgs, encpart, self.session_key = await self.kc.with_clock_skew(self.kc.get_TGS, spn)#, override_etype = self.preferred_etypes)						
						else:
							logger.debug('Failed to get TGT! %s' % e)
							raise e

					except Exception as e:
						raise e
					# if the target server is in a different domain, we need to get a referral ticket
					if self.credential.cross_target is not None:
						# cross-domain kerberos
						ref_tgs, ref_encpart, ref_key, new_factory = await self.kc.with_clock_skew(self.kc.get_referral_ticket, self.credential.cross_realm, self.credential.cross_target.get_ip_or_hostname())
						self.kc = new_factory.get_client()
						spn.domain = self.credential.cross_realm
					tgs, encpart, self.session_key = await self.kc.with_clock_skew(self.kc.get_TGS, spn)#, override_etype = self.preferred_etypes)
				
				logger.debug('TGS: %s' % tgs)
				logger.debug('encpart: %s' % encpart)
				logger.debug('session_key: %s' % self.session_key)

				ap_opts = []
				if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags or GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags:
						ap_opts.append('mutual-required')
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs, 
							encpart, 
							self.session_key, 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts=ap_opts, 
							cb_data = cb_data
						)
					else:
						apreq = construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(),
							self.session_key,
							tgs['crealm'],
							tgs['cname']['name-string'][0],
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts = ap_opts,
							cb_data = cb_data,
							now = self.kc._now(),
						)

					logger.debug('APREQ constructed: %s' % apreq)
					return apreq, True, None

				else:
					#not mutual nor dce auth will take one step only
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs,
							encpart,
							self.session_key,
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts=ap_opts,
							cb_data = cb_data)
					else:
						apreq = construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(),
							self.session_key,
							tgs['crealm'],
							tgs['cname']['name-string'][0],
							flags = self.flags,
							seq_number = self.seq_number,
							ap_opts = ap_opts,
							cb_data = cb_data,
							now = self.kc._now(),
						)
					
					logger.debug('APREQ constructed: %s' % apreq)
					self.gssapi = get_gssapi(self.session_key)
					return apreq, False, None

			else:
				self.seq_number = seq_number

				logger.debug('Processing AP_REP %s' % authData.hex())
				try:
					temp = KRB5_MECH_INDEP_TOKEN.from_bytes(authData)
					try:
						aprep = AP_REP.load(temp.data[2:]).native
					except Exception:
						# Some hosts omit the 2-byte token-type prefix inside the GSSAPI
						# wrapper; try without skipping it before falling back.
						logger.debug('AP_REP load with [2:] failed, retrying without offset hex=%s' % temp.data.hex())
						aprep = AP_REP.load(temp.data).native
				except Exception as e:
					# KRB5_MECH_INDEP_TOKEN.from_bytes() failed — happens on Windows 10
					# workstations that wrap the AP-REP in a GSSAPI token whose OID the
					# parser cannot handle (ObjectIdentifier.load fails on the inner OID).
					# The outer byte is still 0x60 (GSSAPI APPLICATION tag 0).
					#
					# Strategy: if the data starts with 0x60, scan the first 256 bytes for
					# the AP-REP APPLICATION tag 0x6f (APPLICATION CONSTRUCTED 15) and try
					# to parse from each candidate offset.  This extracts the raw AP-REP
					# that Windows 10 embeds inside the GSSAPI wrapper without re-implementing
					# the full GSSAPI/SPNEGO parser.
					logger.debug('AP_REP fallback: GSSAPI parse error=%s raw_hex=%s' % (e, authData.hex()))
					aprep = None
					if authData and authData[0:1] == b'\x60':
						search_window = authData[:256]
						for offset in range(1, len(search_window)):
							if search_window[offset:offset+1] == b'\x6f':
								try:
									aprep = AP_REP.load(authData[offset:]).native
									logger.debug('AP_REP extracted from GSSAPI wrapper at offset=%d' % offset)
									break
								except Exception:
									continue
					if aprep is None:
						# Final fallback: raw bytes (will fail with original error if still 0x60)
						try:
							aprep = AP_REP.load(authData).native
						except Exception as parse_exc:
							raise Exception(
								'Error parsing %s.AP_REP - %s [raw_hex:%s]'
								% (AP_REP.__module__, parse_exc, authData[:32].hex())
							) from parse_exc
				
				logger.debug('AP_REP: %s' % aprep)
				cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
				cipher_text = aprep['enc-part']['cipher']
				temp = cipher.decrypt(self.session_key, 12, cipher_text)
				
				enc_part = EncAPRepPart.load(temp).native
				cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
					
				now = self.kc._now()
				apreppart_data = {}
				apreppart_data['cusec'] = now.microsecond
				apreppart_data['ctime'] = now.replace(microsecond=0)
				apreppart_data['seq-number'] = enc_part['seq-number']
				#print('seq %s' % enc_part['seq-number'])
				#self.seq_number = 0 #enc_part['seq-number']
				
				logger.debug('apreppart_data: %s' % apreppart_data)
				apreppart_data_enc = cipher.encrypt(self.session_key, 12, EncAPRepPart(apreppart_data).dump(), None)
					
				#overriding current session key
				self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
				
				logger.debug('SessionKey: %s' % self.session_key)

				ap_rep = {}
				ap_rep['pvno'] = 5 
				ap_rep['msg-type'] = MESSAGE_TYPE.KRB_AP_REP.value
				ap_rep['enc-part'] = EncryptedData({'etype': self.session_key.enctype, 'cipher': apreppart_data_enc}) 
				
				logger.debug('AP_REP: %s' % ap_rep)
				token = AP_REP(ap_rep).dump()
				if GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					self.gssapi = gssapi_smb(self.session_key)
				else:
					self.gssapi = get_gssapi(self.session_key)
				self.iterations += 1
				return token, True, None
		
		except Exception as e:
			return None, None, e
