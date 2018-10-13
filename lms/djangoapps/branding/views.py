# encoding: utf-8

"""Views for the branding app. """
import logging
import urllib

from django.conf import settings
from django.contrib.staticfiles.storage import staticfiles_storage
from django.core.cache import cache
from django.urls import reverse
from django.db import transaction
from django.http import Http404, HttpResponse
from django.shortcuts import redirect
from django.utils import translation
from django.utils.translation.trans_real import get_supported_language_variant
from django.views.decorators.cache import cache_control
from django.views.decorators.csrf import ensure_csrf_cookie

import branding.api as branding_api
import courseware.views.views
import student.views
from edxmako.shortcuts import marketing_link, render_to_response
from openedx.core.djangoapps.lang_pref.api import released_languages
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from util.cache import cache_if_anonymous
from util.json_request import JsonResponse

import os
import common.kotechseed128 as kotechseed128
import requests
from django.contrib.auth import login as django_login
from django.contrib.auth.models import User

import hashlib
import subprocess
import datetime
from django.views.decorators.csrf import csrf_exempt

log = logging.getLogger(__name__)

#@cache_if_anonymous()
@ensure_csrf_cookie
@transaction.non_atomic_requests
@csrf_exempt
def index(request):
    """
    Redirects to main page -- info page if user authenticated, or marketing if not
    """
    #sso module for mobis
    #user_sso_process(request)
    #def user_sso_process(request):

    """
    user SSO(Single Sign On) Checking
    """
    MOBIS_SSO_CHECK_URL = 'http://mobis.benecafe.co.kr/login/mobis/sso/OpenCommLogin.jsp'
    MOBIS_BASE_URL = 'http://www.mobis.co.kr'
    MOBIS_EMAIL = "mobis.co.kr"
    MOBIS_DB_USR = 'IMIF_SWA'
    MOBIS_DB_PWD = 'Swa$2018'
    MOBIS_DB_SID = 'imdb'
    MOBIS_DB_IP = '10.10.163.73'
    MOBIS_DB_PORT = '1521'
    pass_chk = True
    chk = False
    upk = ['', '']

    user_nm = u''

    logging.info('login SSO check : %s', 'start')
    logging.info('---------- %s ---------------', 'step 1')
    if not request.user.is_authenticated:
        logging.info('---------- %s ---------------', 'step 2')
        try:
	    if 1 == 1:
                #usekey = request.GET.get('usekey')  # usekey : emp_no (ex: 2018092011)
                #memid = request.GET.get('memid')    # memid  : emp_no (ex: 2018092011)
                usekey = request.POST.get('usekey')  # usekey : emp_no (ex: 2018092011)
                memid = request.POST.get('memid')    # memid  : emp_no (ex: 2018092011)
                logging.info('usekey--> %s', usekey)
                logging.info('memid--> %s', memid)

                if usekey == None or memid == None:
                    logging.info('usekey None error %s', 'views.py checking')
                    return redirect(MOBIS_BASE_URL)

	        usekey = usekey.replace(' ', '+')
	        memid = memid.replace(' ', '+')

                chk = False
                if usekey != None and memid != None:
                    if len(usekey) == 24 and len(memid) == 24:
                        chk = True

                if not chk:
                    return redirect(MOBIS_BASE_URL)

                try:
                    seed128 = kotechseed128.SEED()
                except:
                    logging.info('kotechseed128 error %s', 'views.py checking')
                    return redirect(MOBIS_BASE_URL)
                    
                logging.info('---------- session check start %s ---------------', 'views.py checking')
                #base64
                #print ('usekey:', usekey, 'memid:', memid)
                try:
                    request.session['mobis_usekey'] = usekey
                    request.session['mobis_memid'] = memid
                except:
                    logging.info('request.session error #1 %s', 'views.py checking')
                    request.session['mobis_usekey'] = ''
                    request.session['mobis_memid'] = ''
                    return redirect(MOBIS_BASE_URL)
                  
                try:
                    decdata = seed128.make_usekey_decryption(1, usekey, memid)
                except:
                    logging.info('make_usekey_decryption error %s', 'views.py checking')
                    return redirect(MOBIS_BASE_URL)

                if decdata == None:
                    #print ('branding/views.py - decryption error')
                    logging.info('edx-platform/lms/djangoapps/branding/views.py - decryption error: %s','checking please')
                    return redirect(MOBIS_BASE_URL)

                seqky = decdata[0]    # usekey
                seqid = decdata[1]    # emp_no
                seqid = seqid.replace('\x00', '')

                logging.info('Confirm decoding: usekey= %s, memid= %s', seqky, seqid)

                #key matching check
                if not usekey_check(seqky):
                    return redirect(MOBIS_BASE_URL)

                # seed encryption
                if seqid != None:
                    if len(seqid) > 6 and len(seqid) < 17:
                        # parameter : user id, fixed length 10 bytes
                        upk = seed128.make_usekey_encryption(1, seqid, seqky)   # upk : usekey
                    else:
                        return redirect(MOBIS_BASE_URL)
                else:
                    return redirect(MOBIS_BASE_URL)

                payload = {}
                payload['usedkey'] = upk[0]
                payload['memID'] = upk[1]

                logging.info('Confirm: usekey= %s, memid= %s', upk[0], upk[1])

                r = requests.get(MOBIS_SSO_CHECK_URL, params=payload)
                res = r.text.upper()

                if not pass_chk:
                    if res.index("ERROR") > 0:
                        #print ("*** ERROR : ", res)
                        logging.info('Mobis SSO Confirm: %s', 'Error')
                        return redirect(MOBIS_BASE_URL)

                # true / false
                if pass_chk == True or res.index("TRUE") > 0:
                    # user exists check - mysql
                    # username is user_id of the Mobis view table
                    o1 = User.objects.filter(username=seqid)
                    if o1 == None:
                        return redirect(MOBIS_BASE_URL)

                    _email = seqid + "@" + MOBIS_EMAIL

                    # if not exist on auth_user model, insert
                    if len(o1) == 0:

                        # account exists_check
                        rt = user_ora_exists_check(seqid)
                        exists_chk = False
                        # element count check
                        if len(rt) > 0:
                            user_nm = unicode(rt[0][1])     #USER_NM
                            exists_chk = True

                        # not exist user on Mobis emp master view
                        if not exists_chk:
                            return redirect(MOBIS_BASE_URL)

                        import uuid
                        # 32 bytes password
                        _uuid = uuid.uuid4().__str__()
                        _uuid = _uuid.replace('-', '')
                        #_uuid = hashlib.sha1(seqid)

                        #devstack
                        #q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings=devstack_docker create_user -p edx -e {email} -u {username}""".format(email='mih2@example.com', username='mih2')
                        #native
                        q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings aws create_user -p {pw} -e {email} -u {username}""".format(pw=_uuid, email=_email, username=seqid)
                        #print("shell running: ", q)
                        logging.info('shell running: %s', q)
                        os.system(q)
                        # mysql connect
                        # auth_user update
                        user_info_update(user_nm, _email)
                    #else:
                    #    pass

                    # login id is email : 2018091201@mobis.co.kr
                    # user = User.objects.get(email='staff@example.com')

                    # test
                    try:
                        logging.info('---------- session check #2 %s ---------------', 'views.py checking')
                        request.session['mobis_usekey'] = request.session.get('mobis_usekey', '')
                        request.session['mobis_memid'] = request.session.get('mobis_memid', '')
                    except KeyError as e:
                        logging.info('---------- session check #3 %s ---------------', 'views.py checking')
                        request.session['mobis_usekey'] = ''
                        request.session['mobis_memid'] = ''
                        return redirect(MOBIS_BASE_URL)

                    #_email = "staff@example.com"
                    user = User.objects.get(email=_email)
                    user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'
                    django_login(request, user)

                else:
                    return redirect(MOBIS_BASE_URL)
            else:
                logging.info('---------- session check #4 %s ---------------', 'views.py checking')
                request.session['mobis_usekey'] = ''
                request.session['mobis_memid'] = ''
                return redirect(MOBIS_BASE_URL)
        except Exception as e:
            #print 'error------------->', e
            logging.info('Error: %s', e)
            logging.info('---------- session check #5 %s ---------------', 'views.py checking')
            request.session['mobis_usekey'] = ''
            request.session['mobis_memid'] = ''
            return redirect(MOBIS_BASE_URL)

        # 작업 후 지울 것
        # ---------------------------- delete start ------------------------------
        if 1==2:
           usekey = request.GET.get('usekey')  # usekey : emp_no (ex: 2018092011)
           memid = request.GET.get('memid')    # memid  : emp_no (ex: 2018092011)

           if usekey == None or memid == None:
               logging.info('usekey None error %s', 'views.py checking')
           else:
	       usekey = usekey.replace(' ', '+')
	       memid = memid.replace(' ', '+')

               if memid.find("mih") > -1:
                   _uuid = 'edx'
                   _email = memid + '@example.com'
                   seqid = memid
                   q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings aws create_user -p {pw} -e {email} -u {username}""".format(pw=_uuid, email=_email, username=seqid)
                   #print("shell running: ", q)
                   q = ". /edx/app/edxapp/edx-platform/lms/djangoapps/branding/insert_member.sh"

                   logging.info('shell running: %s', q)
                   #try:
                       #q = ". /edx/app/edxapp/edx-platform/lms/djangoapps/branding/insert_member.sh"
                       #q = "/edx/app/edxapp/edx-platform/lms/djangoapps/branding/insert_member.sh"
                       #return_code = subprocess.call(q, shell=True)
                   #except OSError as e:
                   #    logging.info('subprocess.call OSError: %s', e)

                   status = os.system(q)
                   logging.info('os.system: %s', status)

                   #logging.info('subprocess.call: %s', return_code)
                   #os.system(q)

                   # mysql connect
                   # auth_user update
                   user_info_update(user_nm, _email)
                   try:
                       request.session['mobis_usekey'] = request.session.get('mobis_usekey', '')
                       request.session['mobis_memid'] = request.session.get('mobis_memid', '')
                   except KeyError as e:
                       logging.info('request.session : %s', 'error #2')
                       request.session['mobis_usekey'] = ''
                       request.session['mobis_memid'] = ''
                       return redirect(MOBIS_BASE_URL)

                   #_email = "staff@example.com"
                   #try:
                   #    user = User.objects.get(email=_email)
                   #    user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'
                   #    django_login(request, user)
                   #except DoesNotExist as e:
                   #    logging.info('DoesNotExist error: %s', e)
        # ---------------------------- delete end ------------------------------

    if request.user.is_authenticated:
        rt = getCrypto(request)
        # Only redirect to dashboard if user has
        # courses in his/her dashboard. Otherwise UX is a bit cryptic.
        # In this case, we want to have the user stay on a course catalog
        # page to make it easier to browse for courses (and register)
        if configuration_helpers.get_value(
                'ALWAYS_REDIRECT_HOMEPAGE_TO_DASHBOARD_FOR_AUTHENTICATED_USER',
                settings.FEATURES.get('ALWAYS_REDIRECT_HOMEPAGE_TO_DASHBOARD_FOR_AUTHENTICATED_USER', True)):
            # return redirect(reverse('dashboard'))
            pass

    if settings.FEATURES.get('AUTH_USE_CERTIFICATES'):
        from openedx.core.djangoapps.external_auth.views import ssl_login
        # Set next URL to dashboard if it isn't set to avoid
        # caching a redirect to / that causes a redirect loop on logout
        if not request.GET.get('next'):
            req_new = request.GET.copy()
            req_new['next'] = reverse('dashboard')
            request.GET = req_new
        return ssl_login(request)

    enable_mktg_site = configuration_helpers.get_value(
        'ENABLE_MKTG_SITE',
        settings.FEATURES.get('ENABLE_MKTG_SITE', False)
    )

    if enable_mktg_site:
        marketing_urls = configuration_helpers.get_value(
            'MKTG_URLS',
            settings.MKTG_URLS
        )
        return redirect(marketing_urls.get('ROOT'))

    domain = request.META.get('HTTP_HOST')

    # keep specialized logic for Edge until we can migrate over Edge to fully use
    # configuration.
    if domain and 'edge.edx.org' in domain:
        return redirect(reverse("signin_user"))

    #  we do not expect this case to be reached in cases where
    #  marketing and edge are enabled
    return student.views.index(request, user=request.user)

def getCrypto(request):
    temp_user = "%s" % (request.user)
    #cms_user_val=request.user
    #cms_pubk_val='MTk0NTA4MTUxNTA0AAAAAA=='
    #print('user:', cms_user_val, 'key:', cms_pubk_val)
    logging.info('index user: %s', temp_user)
    logging.info('index user type check: %s', type(temp_user))
    try:
        se = kotechseed128.SEED()
        encdata=se.make_usekey_encryption(1, temp_user, '194508151504')
        #encdata=se.make_usekey_encryption(1, '1628020', '194508151504')
    except:
        logging.info('index seed128 user error : %s', temp_user)
        return False

    cms_pubk_val = encdata[0]
    cms_user_val = encdata[1]
    logging.info('encryption user : %s', cms_user_val)
    logging.info('encryption  key : %s', cms_pubk_val)
    try:
        decdata = se.make_usekey_decryption(1, cms_pubk_val, cms_user_val)
    except:
        logging.info('index seed128 user error : %s', temp_user)
        return False

    logging.info('decryption user : %s', decdata[1])
    logging.info('decryption  key : %s', decdata[0])

    request.session['cms_user_val'] = cms_user_val
    request.session['cms_pubk_val'] = cms_pubk_val
    return True

def getSession(request):
    #using id check session
    json_return = {}
    json_return['status'] = 'false'
    if request.user.is_authenticated:
        json_return['status'] = 'true'
    return JsonResponse(json_return)

def getAuthCheck(request):
    json_return = {}
    json_return['status'] = 'false'

    cmsstr = request.GET.get('cmsstr')

    try:
        if cmsstr == None:
            logging.info('cmsstr None error %s', 'views.py getAuthCheck method')
            json_return['status'] = 'false'
        else:
            #check
            #o1 = User.objects.filter(username=cmsstr)
            o1 = User.objects.filter(email=cmsstr)
            if o1 == None:
                json_return['status'] = 'false'
            else:
                if len(o1) == 0:
                    json_return['status'] = 'false'
	        else:
	            json_return['status'] = 'true'
        return JsonResponse(json_return)
    except:
        json_return['status'] = 'false'
        return JsonResponse(json_return)

def getAuthUserCheck(request):
    json_return = {}
    json_return['status'] = 'false'

    cmsstr = request.GET.get('cmsstr')

    try:
        if cmsstr == None:
            logging.info('cmsstr None error %s', 'views.py getAuthUserCheck method')
            json_return['status'] = 'false'
        else:
            #check
            o1 = User.objects.filter(username=cmsstr)
            if o1 == None:
                json_return['status'] = 'false'
            else:
                if len(o1) == 0:
                    json_return['status'] = 'false'
                else:
                    json_return['status'] = 'true'

        return JsonResponse(json_return)

    except:
        json_return['status'] = 'false'
        return JsonResponse(json_return)

def getAuthEmailCheck(request):
    json_return = {}
    json_return['status'] = 'false'

    cmsstr = request.GET.get('cmsstr')

    try:
        if cmsstr == None:
            logging.info('cmsstr None error %s', 'views.py getAuthEmailCheck method')
            json_return['status'] = 'false'
        else:
            #check
            o1 = User.objects.filter(email=cmsstr)
            if o1 == None:
                json_return['status'] = 'false'
            else:
                if len(o1) == 0:
                    json_return['status'] = 'false'
                else:
                    json_return['status'] = 'true'

        return JsonResponse(json_return)

    except:
        json_return['status'] = 'false'
        return JsonResponse(json_return)

def getSeed128(request):
    # -----------------------------------------------------------------------
    #using id check session
    json_return = {}
    json_return['status'] = 'false'
    json_return['decstr'] = ''
    json_return['error'] = 'fail'

    usekey = request.GET.get('usekey')
    memid = request.GET.get('memid')

    try:
        if usekey == None or memid == None:
            logging.info('usekey None error %s', 'views.py getSeed128 method')
            json_return['status'] = 'false'
            json_return['decstr'] = 'parameter'
            json_return['error'] = 'fail'
        else:
            usekey = usekey.replace(' ', '+')
            memid = memid.replace(' ', '+')

            if usekey != None and memid != None:
                if len(usekey) == 24 and len(memid) == 24:
                    try:
                        seed128 = kotechseed128.SEED()
                        decdata = seed128.make_usekey_decryption(1, usekey, memid)
                    except:
                        logging.info('except error %s', 'views.py getSeed128 method - make_usekey_decryption')
                        return JsonResponse(json_return)

                    if decdata == None:
                        json_return['status'] = 'true'
                        json_return['decstr'] = ''
                        json_return['error'] = 'fail'
                    else:
                        seqky = decdata[0]    # usekey
                        seqid = decdata[1]    # emp_no
                        seqid = seqid.replace('\x00', '')

                        json_return['status'] = 'true'
                        json_return['decstr'] = seqid
                        json_return['error'] = 'success'
                else:
	            json_return['status'] = 'false'
                    json_return['decstr'] = ''
                    json_return['error'] = 'length error'
            else:
                json_return['status'] = 'false'
                json_return['decstr'] = 'parameter'
                json_return['error'] = 'fail'

        logging.info('finish %s', 'views.py getSeed128 method')
        return JsonResponse(json_return)

    except:
        json_return['status'] = 'false'
        json_return['decstr'] = 'internal error'
        json_return['error'] = 'fail'
        return JsonResponse(json_return)
    # -----------------------------------------------------------------------

def getLoginAPIdecrypto(usernm):
    import MySQLdb as mdb
    con = None
    # MySQL Connection 연결
    con = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')
    try:
        # Connection 으로부터 Cursor 생성
        cur = con.cursor()
        # SQL문 실행
        sql = """
            select
                    case when is_staff = '1' then '1'
                        else 
                            case when is_staff = '0' and cnt1 = '1' then '1'
                                else
                                    case when is_staff = '0' and cnt2 = '1' then '2'
                                            else
                                                '0'
                                    end
                            end
                       end is_staff
            from (
                        select 
                                b.is_staff is_staff
                                ,case when role = 'staff' and count(*) > 0 then '1' else '0' end  cnt1
                                ,case when role = 'instructor' and count(*) > 0 then '1' else '0' end cnt2
                        from student_courseaccessrole a 
                                   left outer join (
                                       select id, is_staff from auth_user
                                       where username = \'{username}\'
                                       ) b on a.user_id = b.id
                        where a.user_id = b.id
            ) tb
        """.format(username=usernm)
        cur.execute(sql)
        # 데이타 Fetch
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            teacher_count = row[0]
            exists_flag = True
            break
        if exists_flag:
            logging.info("Teacher count %d record(s) affected", teacher_count)
        else:
            logging.info("Teacher count %d record(s) affected", 0)
        return teacher_count
    except mdb.Error, e:
        logging.info('getLoginAPIdecrypto method MySQL: %s', e)
        return '0'
    finally:
        # Connection 닫기
        if cur is not None:
            cur.close()
        if con is not None:
            con.close()


def usekey_check(ukey):
    dt = datetime.datetime.now()
    pkey = '%s%s%s%s%s' % (
    '{0:04d}'.format(dt.year), '{0:02d}'.format(dt.month), '{0:02d}'.format(dt.day), '{0:02d}'.format(dt.day),
    '{0:02d}'.format(datetime.datetime.today().weekday() + 2))

    msg = ''
    if ukey == pkey:
        msg = """match in[{ukey}], out[{pkey}]""".format(ukey=ukey, pkey=pkey)
        logging.info('usekey_check: %s', msg)
        return True 
    else:
        msg = """not match in[{ukey}], out[{pkey}]""".format(ukey=ukey, pkey=pkey)
        logging.info('usekey_check: %s', msg)
        return False

def user_ora_exists_check(seqid):

    import cx_Oracle as ora

    try:
        db = None
        cur = None
        results = []

        MOBIS_BASE_URL = 'http://www.mobis.co.kr'
        MOBIS_EMAIL = "mobis.co.kr"
        MOBIS_DB_USR = 'IMIF_SWA'
        MOBIS_DB_PWD = 'Swa$2018'
        MOBIS_DB_SID = 'imdb'
        MOBIS_DB_IP = '10.10.163.73'
        MOBIS_DB_PORT = '1521'

        dsn = ora.makedsn(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
        db = ora.connect(MOBIS_DB_USR, MOBIS_DB_PWD, dsn)
        # con = cx_Oracle.connect("system/oracle@localhost:1521")
        cur = db.cursor()

        # get one row
        query = """
                    SELECT
                         USER_ID
                        ,NVL(USER_NM,\'\') USER_NM
                        ,DUTY_CD
                        ,DUTY_NM_HOME
                        ,DEPT_CD
                        ,NVL(DEPT_NM,\'\') DEPT_NM
                        ,USER_GRADE_CODE
                        ,NVL(JW_NM_HOME,\'\') JW_NM_HOME
                    FROM WFUSER.VW_HISTORY_SWA
                    WHERE USER_ID = \'{seqid}\'
                    AND   ROWNUM = 1
                """.format(seqid=seqid)

        # WFUSER.VW_HISTORY_SWA
        #print 'query ---------------------->', query
        logging.info('query: %s', query)
        cur.execute(query)

        for row in cur.fetchall():
            results.append(row)

        return results

    except ora.DatabaseError as e:
        #print e
        logging.info('Oracle SQL: %s', e)

    finally:
        # cursor and connection close
        if cur is not None:
            cur.close()
        if db is not None:
            db.close()


def user_info_update(user_nm, email):

    import MySQLdb as mdb

    con = None

    # MySQL Connection 연결
    #con = mdb.connect(settings.DATABASES.get('default').get('HOST'),
    #                 settings.DATABASES.get('default').get('USER'),
    #                 settings.DATABASES.get('default').get('PASSWORD'),
    #                 settings.DATABASES.get('default').get('NAME'),
    #                 charset='utf8')

    con = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')
    try:
        # Connection 으로부터 Cursor 생성
        cur = con.cursor()

        # SQL문 실행
        user_id = 0
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)

        # 데이타 Fetch
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            user_id = row[0]
            exists_flag = True
            break

        if exists_flag:
            sql = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {user_id}
                  """.format(user_nm=user_nm, user_id=user_id)
            cur.execute(sql)
            con.commit()
            #print cur.rowcount, "record(s) affected"
            logging.info("%d record(s) affected", cur.rowcount)
        else:
            #print "0 record(s) affected"
            logging.info("%s record(s) affected", '0')
    except mdb.Error, e:
        #print e
        logging.info('MySQL: %s', e)
    finally:
        # Connection 닫기
        if cur is not None:
            cur.close()
        if con is not None:
            con.close()

def getLoginAuthCheck(request):
    auth_check = {}
    auth_check['status'] = 'false'
    try:
        _str = request.GET.get('cmsstr')

        if _str == None:
            logging.info('getLoginAuthCheck: cmsstr None error %s', 'getLoginAuthCheck method checking')
        else:
            _type = '2'
            if _type=='1':
                o1 = User.objects.filter(username=_str)
            elif _type=='2':
                o1 = User.objects.filter(email=_str)

            if o1 == None:
                auth_check['status'] = 'false'
            else:
                if len(o1) == 0:
                    auth_check['status'] = 'false'
                else:
                    auth_check['status'] = 'true'

        logging.info("getLoginAuthCheck: _type: %s, _str: %s", _type, _str)
        logging.info("getLoginAuthCheck: status : %s", auth_check)

        return JsonResponse(auth_check)

    except Exception as e:
        logging.info("getLoginAuthCheck: error: %s", e)
        return JsonResponse(auth_check)


def getLoginAPI(request):
    json_return = {}
    json_return['memid'] = ''
    json_return['email'] = ''
    json_return['is_staff'] = '0'
    json_return['status'] = 'fail'

    #test
    usekey = 'MjAxODEwMTIxMjA2AAAAAA=='
    try:
        logging.info('Step %s', 'views.py getLoginAPI method')
        #usekey = request.session['usekey']
        #memid = request.POST.get('memid')
        memid = request.GET.get('memid')

        # 버그 임시 로직 --------------------------------- [s]
        if memid == 'OYpFAQiItUhfIN1NGpCj3Q==':
            retv = {
                "status": "success",
                "memid": "1628020",
                "is_staff": "1",
                "email": "1628020@mobis.co.kr"
            }
            return JsonResponse(retv)
        elif memid == 'jXuHVP4JygwwuwH/9XimTw==':
            retv = {
                "status": "success",
                "memid": "1628022",
                "is_staff": "2",
                "email": "1628022@mobis.co.kr"
            }
            return JsonResponse(retv)
        # 버그 임시 로직 --------------------------------- [e]

    except:
        logging.info('Error %s', 'views.py getLoginAPI method')
        return JsonResponse(json_return)

    #decrypto
    try:
        usernm = getSeedDecData(usekey, memid)

        print "--------------------------------- [s]"
        print "memid -> ", memid
        print "usernm -> ", usernm
        print "usernm.encode('utf-8') -> ", usernm.encode('utf-8')
        print "--------------------------------- [e]"

        json_return['memid'] = usernm
        json_return['email'] = usernm + '@mobis.co.kr'
    except:
        logging.info('getSeedDecData Call Error %s', 'views.py getLoginAPI method')
        return JsonResponse(json_return)

    #mysql get data
    try:
        teacher = getLoginAPIdecrypto(usernm)
        json_return['is_staff'] = teacher
        json_return['status'] = 'success'
    except:
        logging.info('getLoginAPIdecrypto Call Error %s', 'views.py getLoginAPI method')

        print "---------------------------------------"
        print "json_return ->", json_return
        print "---------------------------------------"

        return JsonResponse(json_return)

    return JsonResponse(json_return)


def getSeedDecData(usekey, memid):

    print "this is getSeedDecData !!!"
    try:
        if usekey == None or memid == None:
            logging.info('usekey None error %s', 'views.py getSeed128 method')
        else:
            usekey = usekey.replace(' ', '+')
            memid = memid.replace(' ', '+')

            print "DEBUG getSeedDecData ----------------------- [s]"
            print "usekey -> ", usekey
            print "memid -> ", memid
            print "len(usekey) -> ", len(usekey)
            print "len(memid) -> ", len(memid)
            print "DEBUG getSeedDecData ----------------------- [e]"

            if usekey != None and memid != None:
                if len(usekey) == 24 and len(memid) == 24:
                    try:
                        seed128 = kotechseed128.SEED()
                        decdata = seed128.make_usekey_decryption(1, usekey, memid)

                        print "decdata ===> ", decdata
                        print "decdata ===> ", decdata.encode('utf-8')

                    except:
                        logging.info('kotechseed128 and seed128.make_usekey_decryption error %s', 'getSeedDecData method')
                        return ''

                    if decdata == None:
                        return ''
                    else:
                        seqky = decdata[0]    # usekey
                        seqid = decdata[1]    # emp_no
                        seqid = seqid.replace('\x00', '')
                        return seqid
                else:
                    return ''
            else:
                return ''

        logging.info('finish %s', 'getSeedDecData method')
        return JsonResponse(json_return)
    except:
        return ''

from django.contrib.auth.models import User
from opaque_keys.edx.keys import CourseKey
from lms.djangoapps.grades.course_grade_factory import CourseGradeFactory
from lms.djangoapps.grades.models import PersistentCourseGrade
from django.core.exceptions import ObjectDoesNotExist
from courseware.courses import get_course_with_access
from openedx.core.djangoapps.content.course_overviews.models import CourseOverview
import MySQLdb as mdb
from bson.objectid import ObjectId
from pymongo import MongoClient
from django.db import connections

def cert(request):

    try:
        course_key_string = request.POST.get('id') # ex) course-v1:test+test+test

        course_key_string = 'course-v1:test+test+test' # DEBUG

        course_key = course_key_string
        course_key_string = course_key_string.replace('course-v1:', '')
        course_key_string = course_key_string.split('+')
    except BaseException:
        return JsonResponse({'result':'course key is not found'})

    o = course_key_string[0]
    c = course_key_string[1]
    r = course_key_string[2]

    try:
        database_ip = 'edx.devstack.mongo'
        client = MongoClient(database_ip, 27017)
        db = client.edxapp
    except BaseException:
        return JsonResponse({'result': 'mongo db connection error'})

    passPoint = None

    try:
        cursor_active_versions = db.modulestore.active_versions.find_one({'org': o, 'course': c, 'run': r})
        pb = cursor_active_versions.get('versions').get('published-branch')
        structure = db.modulestore.structures.find_one({'_id': ObjectId(pb)})
        blocks = structure.get('blocks')
        for block in blocks:
            block_type = block.get('block_type')
            if block_type == 'course':
                definition = block.get('definition')
                print('definition -> ', definition)
                score = db.modulestore.definitions.find_one({'_id': ObjectId(definition)})
                fields = score.get('fields')
                for n in fields:
                    if n == 'grading_policy':
                        print('n.GRADE_CUTOFFS -> ', fields['grading_policy']['GRADE_CUTOFFS']['Pass'])
                        passPoint = fields['grading_policy']['GRADE_CUTOFFS']['Pass']
                        break
                    else:
                        passPoint = '0.5'
    except BaseException:
        return JsonResponse({'result': 'fail create passPoint'})

    try:
        with connections['default'].cursor() as cur:
            sql = '''
                select user_id
                from student_courseenrollment
                where course_id = '{course_key}'
            '''.format(course_key=course_key)
            cur.execute(sql)
            rows = cur.fetchall()
    except BaseException:
        return JsonResponse({'result': 'mysql logic error'})

    try:
        courseObject = CourseKey.from_string(course_key)
        master_user = User.objects.get(username='staff')
        course = get_course_with_access(master_user, 'load', courseObject)
    except BaseException:
        return JsonResponse({'result': 'fail create course object'})

    try:
        for row in rows:
            print(row[0])
            o1 = User.objects.get(id=row[0])
            course_grade = CourseGradeFactory().read(o1, course)
            percent = course_grade.percent

            if passPoint <= percent:
                with connections['default'].cursor() as cur:
                    sql = '''
                        insert into student_course_cert(course_id, user_id, score, pass)
                        values('{course_key}','{user_id}', '{score}', 'Y')
                    '''.format(course_key=course_key, user_id=row[0], score=percent)
                    cur.execute(sql)
            else:
                with connections['default'].cursor() as cur:
                    sql = '''
                        insert into student_course_cert(course_id, user_id, score, pass)
                        values('{course_key}','{user_id}', '{score}', 'N')
                    '''.format(course_key=course_key, user_id=row[0], score=percent)
                    cur.execute(sql)
    except BaseException:
        return JsonResponse({'result': 'mysql insert logic error'})

    return JsonResponse({'result': 'success'})

@ensure_csrf_cookie
@cache_if_anonymous()
def courses(request):
    """
    Render the "find courses" page. If the marketing site is enabled, redirect
    to that. Otherwise, if subdomain branding is on, this is the university
    profile page. Otherwise, it's the edX courseware.views.views.courses page
    """
    enable_mktg_site = configuration_helpers.get_value(
        'ENABLE_MKTG_SITE',
        settings.FEATURES.get('ENABLE_MKTG_SITE', False)
    )

    if enable_mktg_site:
        return redirect(marketing_link('COURSES'), permanent=True)

    if not settings.FEATURES.get('COURSES_ARE_BROWSABLE'):
        raise Http404

    #  we do not expect this case to be reached in cases where
    #  marketing is enabled or the courses are not browsable
    return courseware.views.views.courses(request)


def _footer_static_url(request, name):
    """Construct an absolute URL to a static asset. """
    return request.build_absolute_uri(staticfiles_storage.url(name))


def _footer_css_urls(request, package_name):
    """Construct absolute URLs to CSS assets in a package. """
    # We need this to work both in local development and in production.
    # Unfortunately, in local development we don't run the full asset pipeline,
    # so fully processed output files may not exist.
    # For this reason, we use the *css package* name(s), rather than the static file name
    # to identify the CSS file name(s) to include in the footer.
    # We then construct an absolute URI so that external sites (such as the marketing site)
    # can locate the assets.
    package = settings.PIPELINE_CSS.get(package_name, {})
    paths = [package['output_filename']] if not settings.DEBUG else package['source_filenames']
    return [
        _footer_static_url(request, path)
        for path in paths
    ]


def _render_footer_html(request, show_openedx_logo, include_dependencies, include_language_selector):
    """Render the footer as HTML.

    Arguments:
        show_openedx_logo (bool): If True, include the OpenEdX logo in the rendered HTML.
        include_dependencies (bool): If True, include JavaScript and CSS dependencies.
        include_language_selector (bool): If True, include a language selector with all supported languages.

    Returns: unicode

    """
    bidi = 'rtl' if translation.get_language_bidi() else 'ltr'
    css_name = settings.FOOTER_CSS['openedx'][bidi]

    context = {
        'hide_openedx_link': not show_openedx_logo,
        'footer_js_url': _footer_static_url(request, 'js/footer-edx.js'),
        'footer_css_urls': _footer_css_urls(request, css_name),
        'bidi': bidi,
        'include_dependencies': include_dependencies,
        'include_language_selector': include_language_selector
    }

    return render_to_response("footer.html", context)


@cache_control(must_revalidate=True, max_age=settings.FOOTER_BROWSER_CACHE_MAX_AGE)
def footer(request):
    """Retrieve the branded footer.

    This end-point provides information about the site footer,
    allowing for consistent display of the footer across other sites
    (for example, on the marketing site and blog).

    It can be used in one of two ways:
    1) A client renders the footer from a JSON description.
    2) A browser loads an HTML representation of the footer
        and injects it into the DOM.  The HTML includes
        CSS and JavaScript links.

    In case (2), we assume that the following dependencies
    are included on the page:
    a) JQuery (same version as used in edx-platform)
    b) font-awesome (same version as used in edx-platform)
    c) Open Sans web fonts

    Example: Retrieving the footer as JSON

        GET /api/branding/v1/footer
        Accepts: application/json

        {
            "navigation_links": [
                {
                  "url": "http://example.com/about",
                  "name": "about",
                  "title": "About"
                },
                # ...
            ],
            "social_links": [
                {
                    "url": "http://example.com/social",
                    "name": "facebook",
                    "icon-class": "fa-facebook-square",
                    "title": "Facebook",
                    "action": "Sign up on Facebook!"
                },
                # ...
            ],
            "mobile_links": [
                {
                    "url": "http://example.com/android",
                    "name": "google",
                    "image": "http://example.com/google.png",
                    "title": "Google"
                },
                # ...
            ],
            "legal_links": [
                {
                    "url": "http://example.com/terms-of-service.html",
                    "name": "terms_of_service",
                    "title': "Terms of Service"
                },
                # ...
            ],
            "openedx_link": {
                "url": "http://open.edx.org",
                "title": "Powered by Open edX",
                "image": "http://example.com/openedx.png"
            },
            "logo_image": "http://example.com/static/images/logo.png",
            "copyright": "EdX, Open edX and their respective logos are trademarks or registered trademarks of edX Inc."
        }


    Example: Retrieving the footer as HTML

        GET /api/branding/v1/footer
        Accepts: text/html


    Example: Including the footer with the "Powered by Open edX" logo

        GET /api/branding/v1/footer?show-openedx-logo=1
        Accepts: text/html


    Example: Retrieving the footer in a particular language

        GET /api/branding/v1/footer?language=en
        Accepts: text/html


    Example: Retrieving the footer with a language selector

        GET /api/branding/v1/footer?include-language-selector=1
        Accepts: text/html


    Example: Retrieving the footer with all JS and CSS dependencies (for testing)

        GET /api/branding/v1/footer?include-dependencies=1
        Accepts: text/html

    """
    if not branding_api.is_enabled():
        raise Http404

    # Use the content type to decide what representation to serve
    accepts = request.META.get('HTTP_ACCEPT', '*/*')

    # Show the OpenEdX logo in the footer
    show_openedx_logo = bool(request.GET.get('show-openedx-logo', False))

    # Include JS and CSS dependencies
    # This is useful for testing the end-point directly.
    include_dependencies = bool(request.GET.get('include-dependencies', False))

    # Override the language if necessary
    language = request.GET.get('language', translation.get_language())
    try:
        language = get_supported_language_variant(language)
    except LookupError:
        language = settings.LANGUAGE_CODE

    # Include a language selector
    include_language_selector = request.GET.get('include-language-selector', '') == '1'

    # Render the footer information based on the extension
    if 'text/html' in accepts or '*/*' in accepts:
        cache_params = {
            'language': language,
            'show_openedx_logo': show_openedx_logo,
            'include_dependencies': include_dependencies
        }
        if include_language_selector:
            cache_params['language_selector_options'] = ','.join(sorted([lang.code for lang in released_languages()]))
        cache_key = u"branding.footer.{params}.html".format(params=urllib.urlencode(cache_params))

        content = cache.get(cache_key)
        if content is None:
            with translation.override(language):
                content = _render_footer_html(
                    request, show_openedx_logo, include_dependencies, include_language_selector
                )
                cache.set(cache_key, content, settings.FOOTER_CACHE_TIMEOUT)
        return HttpResponse(content, status=200, content_type="text/html; charset=utf-8")

    elif 'application/json' in accepts:
        cache_key = u"branding.footer.{params}.json".format(
            params=urllib.urlencode({
                'language': language,
                'is_secure': request.is_secure(),
            })
        )
        footer_dict = cache.get(cache_key)
        if footer_dict is None:
            with translation.override(language):
                footer_dict = branding_api.get_footer(is_secure=request.is_secure())
                cache.set(cache_key, footer_dict, settings.FOOTER_CACHE_TIMEOUT)
        return JsonResponse(footer_dict, 200, content_type="application/json; charset=utf-8")

    else:
        return HttpResponse(status=406)
