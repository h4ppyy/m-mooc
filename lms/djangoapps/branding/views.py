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
import kotechseed128
import requests
from django.contrib.auth.models import User

log = logging.getLogger(__name__)


#@ensure_csrf_cookie
#@transaction.non_atomic_requests
#@cache_if_anonymous()
def index(request):
    """
    Redirects to main page -- info page if user authenticated, or marketing if not
    """

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


    request.session['mobis_usekey'] = ''
    request.session['mobis_memid']  = ''

    usekey = request.GET.get('usekey')  # usekey : emp_no (ex: 2018092011)
    memid = request.GET.get('memid')    # memid  : emp_no (ex: 2018092011)

    #logging.info('hello world')
    #logging.info(usekey)
    #logging.info(type(usekey))

    logging.info('val ---------------------->', usekey)
    logging.info('type ---------------------->', type(usekey))
    log.info('val ---------------------->', usekey)
    log.info('type ---------------------->', type(usekey))

    if usekey != None:
        if not request.user.is_authenticated:
	    try:
		if 1 == 0:

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
			print ('branding/views.py - decryption error')
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
			    print ("*** ERROR : ", res)
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

			    import cx_Oracle
			    import uuid

			    #dsn = cx_Oracle.makedsn(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
			    #db = cx_Oracle.connect(MOBIS_DB_USR, MOBIS_DB_PWD, dsn)
                            db = cx_Oracle.connect("IMIF_SWA", "Swa$2018", "10.10.163.73:1521/imdb")
			    #con = cx_Oracle.connect("system/oracle@localhost:1521")
			    cur = db.cursor()

			    # get one row
			    query = """
		            	select
		                     USER_ID
		                    ,USER_NM
		                    ,DUTY_CD
		                    ,DUTY_NM_HOME
		                    ,DEPT_CD
		                    ,DEPT_NM
		                    ,USER_GRADE_CODE
		                    ,JW_NM_HOME
		                from WFUSER.VW_HISTORY_SWA
		                where USER_ID = \'{seqid}\'
		               """.format(seqid=seqid)

			    #query = """select * from WFUSER.VW_HISTORY_SWA where USER_ID = \'{seqid}\'""".format(seqid=seqid)
                            log.info('query ---------------------->', query)
			    cur.execute(query)
			    # rows = cur.fetchone()

			    results = []
			    exists_chk = False
			    for row in cur.fetchall():
				results.append(row)
				exists_chk = True

			    #cursor and connection close
			    cur.close()
			    db.close()

			    # not exist user on Mobis emp master view
			    if not exists_chk:
				return redirect(MOBIS_BASE_URL)

			    # 32 bytes password
			    _uuid = uuid.uuid4().__str__()
			    _uuid = _uuid.replace('-', '')

			    #devstack
			    #q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings=devstack_docker create_user -p {pw} -e {email} -u {username}""".format(pw=_uuid, email=_email, username=seqid)
			    #native
			    q = """sudo -u edxapp /edx/bin/python.edxapp /edx/app/edxapp/edx-platform/manage.py lms --settings=aws create_user -p {pw} -e {email} -u {username}""".format(pw=_uuid, email=_email, username=seqid)
			    #print("shell running: ", q)
                            log.info('shell running ---------------------->', q)
			    os.system(q)
		    else:
			return redirect(MOBIS_BASE_URL)
		else:
		    pass
	    except Exception as e:
		print str(e)
		raise

	    # login id is email : 2018091201@mobis.co.kr
	    #user = User.objects.get(email='staff@example.com')

            logging.info('_email ---------------------->', _email)
	    user = User.objects.get(email=_email)
	    user.backend = 'ratelimitbackend.backends.RateLimitModelBackend'

    if request.user.is_authenticated:
        # Only redirect to dashboard if user has
        # courses in his/her dashboard. Otherwise UX is a bit cryptic.
        # In this case, we want to have the user stay on a course catalog
        # page to make it easier to browse for courses (and register)
        if configuration_helpers.get_value(
                'ALWAYS_REDIRECT_HOMEPAGE_TO_DASHBOARD_FOR_AUTHENTICATED_USER',
                settings.FEATURES.get('ALWAYS_REDIRECT_HOMEPAGE_TO_DASHBOARD_FOR_AUTHENTICATED_USER', True)):
            return redirect(reverse('dashboard'))

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

def getSession(request):
    #using id check session
    session_exists_check = {}
    session_exists_check['status'] = 'false'
    if request.user.is_authenticated:
        session_exists_check['status'] = 'true'
    #print "--> session_exists_check:", session_exists_check
    return JsonResponse(session_exists_check)

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
