#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import requests
import urllib
import uuid
import json
import hashlib
import base64
import argparse

#https://openbanking.siauliubankas.lt 
#https://openbank.sb.lt
class Connector(object):
	"""docstring for SauliuBankas"""
	def __init__(self, pach, usrpwd):
		super(Connector, self).__init__()
		self.pach = pach
		self.headers ={
		'accept'		: 'application/json',
		#'user-agent'	: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36',
		#'accep-encoding': 'gzip, deflate, br',
		"content-type"  :'application/json;charset=UTF-8'
		}
		self.login(usrpwd)
	
	def __new__(self, pach, usrpwd):
		if not hasattr(self, 'instance'):
			self.instance = super(Connector,self).__new__(self)
		return self.instance

	def login(self, usrpwd):
		response = self.POST("/frontapi/users/login",usrpwd,self.headers)
		#print(response.status_code)
		for k, v in response.cookies.get_dict().items():
			self.headers["cookie"]="{0}={1}".format(k,urllib.parse.unquote(v))

	def POST(self,req,data,headers):
		return requests.post("{0}{1}".format(self.pach,req),headers=headers,json=data)

	def GET(self, req, headers):
		return requests.get("{0}{1}".format(self.pach,req),headers=headers)



class APIexpl(object):
	"""docstring for APIexpl"""
	def __init__(self, cn):
		super(APIexpl, self).__init__()
		self.cn = cn

	def accounts(self,ConsentID):
		headers = self.cn.headers.copy()
		headers["X-Request-ID"]=str(uuid.uuid1())
		headers["Consent-ID"]=ConsentID
		return self.cn.GET("/psd2/v1/accounts",headers)
	
	def transactions(self,ConsentID,resourceId):
		headers = self.cn.headers.copy()
		headers["X-Request-ID"]=str(uuid.uuid1())
		headers["bookingStatus"]="booked"
		headers["account-id"]=resourceId
		headers["Consent-ID"]=ConsentID
		return self.cn.GET("/psd2/v1/accounts/{}/transactions?bookingStatus=booked".format(resourceId),headers)

	def transaction(self,ConsentID,resourceId,transactionId):
		headers = self.cn.headers.copy()
		headers["X-Request-ID"]=str(uuid.uuid1())
		headers["account-id"]=resourceId
		headers["Consent-ID"]=ConsentID
		headers["transactionId"]=transactionId
	
		return self.cn.GET("/psd2/v1/accounts/{0}/transactions/{1}".format(resourceId,transactionId),headers)
	

class Concent(object):
	"""docstring for Concent"""
	def __init__(self, cn):
		super(Concent, self).__init__()
		self.cn = cn

	def concent(self,tpp,tpp_private,acc_list,email):
		headers = self.cn.headers.copy()
		json = self.cr_json(acc_list)
		self.add_Digest(headers, json)
		self.add_TPPSignature(headers,tpp)
		self.add_PSUID(headers)
		self.add_PSUIPAddress(headers)	
		self.add_Signature(headers,tpp_private)	
		headers["PSU-Geo-Location"] = email
		return self.cn.POST("/psd2/v1/concent",json,headers)	

	def add_Digest(self,headers, json):
		headers["Digest"] = 'SHA-256=ae00d5d89f93a027a529ad68b95c4d9a8df621dd0be8c941c611c2dad8a19274'	
	
	def add_Signature(self,headers,tpp_private):
		headers["Signature"] = 'keyId="SN = 01020306, CA = CN=OpenBanking", algorithm="rsa-sha256", headers="digest x-request-id", signature = "k2rWRpL6eKm6xaltBonAYUbzrqOMzTXOUkRqY3TtT/L8LJU0bOPEsCeJPv/wBHB5r42Nvxa+b6y+bThpqqqVoZQ67B9CKjmBnGDtIYxeuB9ugCJhua5dmDWn1O+yIL3IVfGYL4TtqEzE/DQucwoXQNzTEkDtqRAv2fqr052uUY/snGYM6/WVnLEKs7TNWVjMFWHOd+0k2ggiMUttpV9+XyPNnLapzBsTKj3xc5uFNoXjkzKbecFzCTAMCPNEysxburY+VbMsiqrPzlHG26qvstKEgMU8nodlLz9WmE+gV2YfppTmHV6Na/aEgaDy+P49KTOvubmqST7sBIfTpkju5w=="'
	
	def add_TPPSignature(self,headers,tpp):
		headers["TPP-Signature-Certificate"] = 'MIIC0DCCAbigAwIBAgIEAQIDBjANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDEwtPcGVuQmFua2luZzAeFw0xOTA2MTMwNzM2MjdaFw0yMDA2MTMwNzM2MjdaMC0xKzApBgNVBAMeIgBvAHAAZQBuAGIAYQBuAGsAaQBuAGcAQABzAGIALgBsAHQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDyx+o7eQuDDEtHpC/MfdTOarrk1uiuQW7pXbmB5sUoSK1AyjuWY1065nyJf59i7BWR4jqnpbQTCOMq2EtDODV7CpjSJhhcyxoXIujXcZU+tTBPNVJ8MVBP8YaYEzcmO8oRNENRG0oEyCgAhiF5zpW/7MG/sKb3bvMU3Pd5jca/NIMZaSiTGoHj04rNkk79QD2Lkqw0oEb0bAfSJYehCLTW4GxGqF30ymQma2Qy5Szr3KxsxK77tNEusNKkPzMW+01rBsQlv/QF8vk9xPjLl+EL131bFWyuspk2PPcC2+2j+Uv1adDZiaHR9aHrRQy14fb50tGgBAhk5y7SQ9DdPn3dAgMBAAGjDzANMAsGA1UdDwQEAwIGwDANBgkqhkiG9w0BAQsFAAOCAQEAYS6HUUS3li01MFojCYktYN5JtzhjIJJ7Zk9EWjTnbwc/oE7Y1G16Eu0kZUcOzfYHRnk/JQcMxejBY7CP6cQm98jsJA4a9oT7/ToppH1Eyf2iDfoh54BWB/fd1F8qhSXyj1NvJetccplbIQPEHqp7QVFvBEjMe/w+YfGhAF4D2kbwa9e6xPBe0nwqVk7Rnf7k30JNWiu7CjLERJQplif2Ardk6ofn6HUBaAxKfLRtInVwogpK/3TYE4VtSqItoLTtapPaYmaEhZ6E1lvbAoQfHDliwzevcK+x69FeXgfWwrmi9yFX5V+mxWlZs64PwGTKwBFz4/2UkUHKRwYsspeg5Q=='

	def add_PSUID(self,headers):	
		headers["PSU-ID"] = 'PSU_123456789'

	def add_PSUIPAddress(self,headers):	
		headers["PSU-IP-Address"] = '192.168.0.1'	

	def cr_json(self,acc_list):
		dt = {
		"access":{"accounts": [],"balances": [],"transactions": [] } ,
		"recurringIndicator": False,
		"combinedServiceIndicator": False,
		"frequencyPerDay": 1,
		"validUntil": "2021-01-01"
		}
		for acc in acc_list:
			iban, currency = acc.split(":")
			dt["access"]["accounts"].append({"iban":iban, "currency": currency})
			dt["access"]["balances"].append({"iban":iban, "currency": currency})
			dt["access"]["transactions"].append({"iban":iban, "currency": currency})
		return dt


	def tst(self):
		return
		{
 			"validUntil" : "2019-02-06",
 			 "frequencyPerDay" : 1,
  			"recurringIndicator" : True,
  			"combinedServiceIndicator" : False,
 			 "access" : {
 			 "accounts" : [ {
 			 "iban" : "BE86973764000422"
 			 } ],
 			 "balances" : [ {
 			 "iban" : "BE84973772586995"
 			 } ],
 			 "transactions" : [ {
 			 "iban" : "BE53973751652916"
 			 } ]
 			 }
 			}

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-U','--user' ,
	metavar="email:login",
	help='openbanking user',
	nargs=1,type=str, required=True)	
	args= vars(parser.parse_args())
	email, password = args["user"][0].split(":")

	pach = "https://openbanking.siauliubankas.lt"
	ConsentID = "C_ID_123456789"
	ACC_ID="ACC_ID_123456789"
	acc_list = ["LT601010012345678901:EUR"]



	cn = Connector(pach	,{"email": email, "password": password})
	#headers = cn.headers.copy()
	#headers["X-Request-ID"]=str(uuid.uuid1())
	#ae = APIexpl(cn)

	co = Concent(cn)
	response = co.concent("tpp","tpp_private",acc_list,email)
	#https://openbanking.siauliubankas.lt/psd2//v1//consents/C_ID_123456789/authorisations ???


	#dmp = json.dumps(Concent.cr_json(None,acc_list)).encode()
	#print(dmp)
	#dk = hashlib.sha256(dmp).hexdigest()
	#print(dk)
	#dk = base64.b64encode(bytes(dk,"utf-8"))
	#print(dk)
	
	#response =ae.accounts(ConsentID)
	#response =ae.transactions(ConsentID,"ACC_ID_123456789")
	#response =ae.transaction(ConsentID,ACC_ID,"TRANID123456789")
	#response = cn.GET("/psd2/v1/consents/C_ID_123456789/authorisations",headers)

	print(response.status_code)
	print(response.text)	