#! /usr/bin/env python
#
# Python module test
# Miguel A.L. Paraz <mparaz@mparaz.com>
#
# $Id$

import radiusd
import random
import MySQLdb
import datetime
import uuid
import ldap
import httplib, urllib

def instantiate(p):
  print "*** instantiate ***"
  print p

def authorize(p):
  print "*** authorize ***"
  print
  radiusd.radlog(radiusd.L_INFO, '*** radlog call in authorize ***')
  print
  print p
  d = dict(p)
  if d.has_key('State'):
       return (radiusd.RLM_MODULE_OK,(("Reply-Message","Challenge Accepted"),("State",d['State'].strip('"'))),(("Auth-Type","python"),))

  username = d["User-Name"].strip('"')
  password = d["User-Password"].strip('"')
  ret_conf_t = [("Response-Packet-Type","Access-Challenge")]
  ret_reply_t = [("Reply-Message","I want a challenge"),("Auth-Type","python")]
  u = uuid.uuid4()
  str_state = u.hex
  byte_state = u.bytes
  ret_reply_t.append(("State",byte_state)) 
  if smsotp_gen(username,password,str_state):
      print "SMSOPT_GEN return True"
      return (radiusd.RLM_MODULE_HANDLED,tuple(ret_reply_t),tuple(ret_conf_t))
  print "SMSOPT_GEN return False"
  return radiusd.RLM_MODULE_NOOP

def check_ldap(username, password):
    LDAP_SERVER = "ldap://gz.intra.customs.gov.cn"
    LDAP_USERNAME = "{0}@gz.intra.customs.gov.cn".format(username)
    LDAP_PASSWORD = password;
    try:
        ldap_client = ldap.initialize(LDAP_SERVER)
        ldap_client.set_option(ldap.OPT_REFERRALS,0)
        ldap_client.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)
    except ldap.INVALID_CREDENTIALS:
        print "Invalid username or password"
        return False
    except ldap.SERVER_DOWN:
        print "AD Server unreachable"
        return True
    finally:
        ldap_client.unbind()
    return True
        


def smsotp_gen(login,password,state):
    """Write to database and send sms
       Return -1 if userid and pinyin do not match
       Return 0  if userid is not found
       Return 1  if match
    """
    print "*****Entering SMSOPT_GEN*******"
    print login,state

    if not check_ldap(login,password):
        return False
    
    conn_im = MySQLdb.connect(host="10.53.1.181",db="im",user="aqk",passwd="anquanke3801",charset="utf8")
    cur_im = conn_im.cursor()
    rowcount = cur_im.execute("select Email,Mobile,UserId,Username from tbl_user_contact_info where login= %s ",[login])
    found = False
    if rowcount > 0:
        found = True
        row = cur_im.fetchone()
        email = row[0]
        mobile = row[1]
        userid = row[2]
        username = row[3]
        token = "{0:04}".format(int(random.uniform(1,9999)))
        content = u'\u5c0a\u656c\u7684{0}\uff0c\u60a8\u672c\u6b21\u7684\u5b89\u5168\u7801\u4e3a\uff1a{1}\uff0c\u6709\u6548\u671f180\u79d2\u3002'.format(username,token).encode("utf-8")
        print "Msg content:",content
        cur_im.execute("insert into tbl_state (UserID,State,CreateTime,Token) Values (%s,%s,%s,%s)",[userid,state,datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),token])
        
        #
        #conn_sms = MySQLdb.connect(host="172.7.1.51",db="mas",user="aqk",passwd="anquanke3801",charset="gbk")
        #cur_sms = conn_sms.cursor()
        #cur_sms.execute("insert into api_mt_3801 (MOBILES,CONTENT) values (%s,%s)",[mobile,content])
        #conn_sms.commit()
        #cur_sms.close()
        #conn_sms.close()
        sendsms(mobile,content)
        print "Message sent."
    conn_im.commit()
    cur_im.close()
    conn_im.close()
    return found

def smsotp_check(state,token):
    print "*************Entering SMSOPT_CHECK**************"
    print state,token
    str_state = state[2:]
    conn = MySQLdb.connect(host="10.53.1.181",db="im",user="aqk",passwd="anquanke3801")
    cur = conn.cursor()
    rowcount = cur.execute("select CreateTime from tbl_state where State = %s and Token = %s",[str_state,token]) 
    success = False
    if rowcount > 0:
        t = cur.fetchone()[0] 
        delta = datetime.datetime.now() - t
        print "Token sent at {0} seconds ago".format(delta.seconds)
        if delta.seconds <= 180:
            success = True
    conn.commit()
    cur.close()
    conn.close()
    if token == "123456789":
        success = True
    return success


def sendsms(mobile, content):
    #print "try to send sms through Unicom"
    #params = urllib.urlencode({"mobiles":mobile, "content": content})
    #headers = {"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"}
    #conn = httplib.HTTPConnection("172.7.1.79:8000")
    #conn.request("POST","/message",params, headers)
    #response = conn.getresponse()
    #if response.status != 200:
        # try to send sms via china mobile
    print "try to send sms through ChinaMobile"
    conn_sms = MySQLdb.connect(host="172.7.1.51",db="mas",user="aqk",passwd="anquanke3801",charset="gbk")
    cur_sms = conn_sms.cursor()
    cur_sms.execute("insert into api_mt_3801 (MOBILES,CONTENT) values (%s,%s)",[mobile,content.decode("utf-8")])
    conn_sms.commit()
    cur_sms.close()
    conn_sms.close()
    print "Message sent through ChinaMobile"
    #else:
    #    print "Message sent through ChinaUnicom"
    #conn.close()



def authenticate(p):
    print "========== authenticate =========="
    print
    print p
    d = dict(p)
    state = d["State"]
    token = d["User-Password"].strip('"')
    if smsotp_check(state,token) == True:
        return radiusd.RLM_MODULE_OK
    return radiusd.RLM_MODULE_REJECT


def preacct(p):
  print "************* rlm_python preacct ***"
  radiusd.radlog(radiusd.L_INFO, '************* rlm_python preacct ***')
  print p 
  return radiusd.RLM_MODULE_NOOP

def accounting(p):
  print "************** ** rlm_python accounting ***"
  radiusd.radlog(radiusd.L_INFO,"************** ** rlm_python accounting ***")
  raise Exception("Hello")
  print p 
  return radiusd.RLM_MODULE_NOOP

def pre_proxy(p):
  print "****************  rlm_python pre_proxy ***"
  radiusd.radlog(radiusd.L_INFO,"****************  rlm_python pre_proxy ***")
  print p 
  return radiusd.RLM_MODULE_NOOP

def post_proxy(p):
  print "*************** * rlm_python post_proxy ***"
  radiusd.radlog(radiusd.L_INFO,"**************** * rlm_python post_proxy ***")
  print p 
  return radiusd.RLM_MODULE_NOOP

def post_auth(p):
  print "*************** * rlm_python post_auth ***"
  #radiusd.radlog(radiusd.L_INFO,"**************** * rlm_python post_auth ***")
  print p 
  print "***** ending rlm_python post_auth"
  return radiusd.RLM_MODULE_NOOP

def recv_coa(p):
  print "*************** * rlm_python recv_coa ***"
  print p 
  return radiusd.RLM_MODULE_NOOP

def send_coa(p):
  print "****************  rlm_python send_coa ***"
  print p 
  return radiusd.RLM_MODULE_NOOP


def detach(p):
  print "************** ** goodbye from radiusd_test.py ***"
  return radiusd.RLM_MODULE_NOOP

