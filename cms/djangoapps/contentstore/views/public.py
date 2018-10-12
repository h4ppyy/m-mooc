# encoding: utf-8

"""
Public views
"""
from django.conf import settings
from django.template.context_processors import csrf
from django.urls import reverse
from django.shortcuts import redirect
from django.views.decorators.clickjacking import xframe_options_deny
from django.views.decorators.csrf import ensure_csrf_cookie

from edxmako.shortcuts import render_to_response
from openedx.core.djangoapps.external_auth.views import redirect_with_get, ssl_get_cert_from_request, ssl_login_shortcut
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from waffle.decorators import waffle_switch
from contentstore.config import waffle

import os
import common.kotechseed128 as kotechseed128
import requests
from django.contrib.auth import authenticate, load_backend, login as django_login, logout
from django.contrib.auth.models import User
import logging
from util.json_request import JsonResponse

log = logging.getLogger(__name__)

__all__ = ['signup', 'login_page', 'howitworks', 'accessibility']


@ensure_csrf_cookie
@xframe_options_deny
def signup(request):
    """
    Display the signup form.
    """
    csrf_token = csrf(request)['csrf_token']
    if request.user.is_authenticated:
        return redirect('/course/')
    if settings.FEATURES.get('AUTH_USE_CERTIFICATES_IMMEDIATE_SIGNUP'):
        # Redirect to course to login to process their certificate if SSL is enabled
        # and registration is disabled.
        return redirect_with_get('login', request.GET, False)

    return render_to_response('register.html', {'csrf': csrf_token})


@ssl_login_shortcut
@ensure_csrf_cookie
@xframe_options_deny
def login_page(request):
    """
    Display the login form.
    """
    csrf_token = csrf(request)['csrf_token']
    if (settings.FEATURES['AUTH_USE_CERTIFICATES'] and
            ssl_get_cert_from_request(request)):
        # SSL login doesn't require a login view, so redirect
        # to course now that the user is authenticated via
        # the decorator.
        next_url = request.GET.get('next')
        if next_url:
            return redirect(next_url)
        else:
            return redirect('/course/')
    if settings.FEATURES.get('AUTH_USE_CAS'):
        # If CAS is enabled, redirect auth handling to there
        return redirect(reverse('cas-login'))

    return render_to_response(
        'login.html',
        {
            'csrf': csrf_token,
            'forgot_password_link': "//{base}/login#forgot-password-modal".format(base=settings.LMS_BASE),
            'platform_name': configuration_helpers.get_value('platform_name', settings.PLATFORM_NAME),
        }
    )

def howitworks(request):
    "Proxy view"
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
    #_email = "staff@example.com"
    #user = User.objects.get(email=_email)
    #user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'
    #django_login(request, user)

    #request.session['mobis_usekey'] = ''
    #request.session['mobis_memid'] = ''

    if not request.user.is_authenticated:
        try:
            if 1 == 1:
                usekey = request.GET.get('usekey')  # usekey : emp_no (ex: 2018092011)
                memid = request.GET.get('memid')    # memid  : emp_no (ex: 2018092011)

                if usekey == None or memid == None:
                    logging.info('usekey None: %s', 'public.py checking')
                    return redirect(MOBIS_BASE_URL)

                usekey = usekey.replace(' ', '+')
                memid = memid.replace(' ', '+')

                chk = False
                if usekey != None and memid != None:
                    if len(usekey) == 24 and len(memid) == 24:
                        chk = True

                if not chk:
                    return redirect(MOBIS_BASE_URL)

                seed128 = kotechseed128.SEED()

                #base64
                #print ('usekey:', usekey, 'memid:', memid)

                request.session['mobis_usekey'] = usekey
                request.session['mobis_memid'] = memid

                decdata = seed128.make_usekey_decryption(1, usekey, memid)

                if decdata == None:
                    #print ('branding/views.py - decryption error')
                    logging.info('edx-platform/cms/djangoapps/contentstore/views/public.py - decryption error: %s','checking please')
                    return redirect(MOBIS_BASE_URL)

                seqky = decdata[0]    # usekey
                seqid = decdata[1]    # emp_no
                seqid = seqid.replace('\x00', '')

                # seed encryption
                if seqid != None:
                    if len(seqid) > 6 and len(seqid) < 17:
                        chk = True
                        # parameter : user id, fixed length 10 bytes
                        upk = seed128.make_usekey_encryption(1, seqid, seqky)   # upk : usekey
                    else:
                        return redirect(MOBIS_BASE_URL)
                else:
                    return redirect(MOBIS_BASE_URL)

                payload = {}
                payload['usedkey'] = upk[0]
                payload['memID'] = upk[1]

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

                        #devstack
                        #q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings=devstack_docker create_user -p {pw} -e {email} -u {username}""".format(pw=_uuid, email=_email, username=seqid)
                        #q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings=devstack_docker create_user -p edx -e {email} -u {username}""".format(email=_email, username=seqid)
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
                        request.session['mobis_usekey'] = request.session.get('mobis_usekey', '')
                        request.session['mobis_memid'] = request.session.get('mobis_memid', '')
                    except KeyError as e:
                        request.session['mobis_usekey'] = ''
                        request.session['mobis_memid'] = ''

                    #_email = "staff@example.com"
                    user = User.objects.get(email=_email)
                    user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'
                    django_login(request, user)

                else:
                    return redirect(MOBIS_BASE_URL)
            else:
                request.session['mobis_usekey'] = ''
                request.session['mobis_memid'] = ''
        except Exception as e:
            #print 'error------------->', e
            logging.info('Error: %s', e)
            request.session['mobis_usekey'] = ''
            request.session['mobis_memid'] = ''
            return redirect(MOBIS_BASE_URL)

    if request.user.is_authenticated:
        return redirect('/home/')
    else:
        return render_to_response('howitworks.html', {})


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
            print cur.rowcount, "record(s) affected"
            logging.info("%d record(s) affected", cur.rowcount)
        else:
            print "0 record(s) affected"
            logging.info("%s record(s) affected", '0')

    except mdb.Error, e:
        print e
        logging.info('MySQL: %s', e)

    finally:
        # Connection 닫기
        if cur is not None:
            cur.close()
        if con is not None:
            con.close()

@waffle_switch('{}.{}'.format(waffle.WAFFLE_NAMESPACE, waffle.ENABLE_ACCESSIBILITY_POLICY_PAGE))
def accessibility(request):
    """
    Display the accessibility accommodation form.
    """

    return render_to_response('accessibility.html', {
        'language_code': request.LANGUAGE_CODE
    })
