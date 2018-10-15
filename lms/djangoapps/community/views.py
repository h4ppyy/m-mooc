# -*- coding: utf-8 -*-
""" Views for a student's account information. """

import json
from django.conf import settings
from django.http import (
    HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpRequest
)
from django.shortcuts import redirect
from django.views.decorators.csrf import ensure_csrf_cookie
from edxmako.shortcuts import render_to_response
from util.json_request import JsonResponse
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
import MySQLdb as mdb
from django.core.serializers.json import DjangoJSONEncoder
from django.core.mail import send_mail
import sys
import re
from django.db import models, connections
from django.forms.models import model_to_dict
from django.core.paginator import Paginator
from django.db.models import Q
import os.path
import datetime
from django.db import connections
from django.core.urlresolvers import reverse

import logging

reload(sys)
sys.setdefaultencoding('utf8')

def comm_list(request, section=None, curr_page=None):
    if request.is_ajax():

        page_size = request.POST.get('page_size')
        curr_page = request.POST.get('curr_page')
        search_con = request.POST.get('search_con')
        search_str = request.POST.get('search_str')

        if search_str != '':
            request.session['search_str'] = search_str

        if search_str == '' and 'search_str' in request.session:
            search_str = request.session['search_str']
            del request.session['search_str']

        print "--------------------> search_str [s]"
        print "search_str = ", search_str
        if 'search_str' in request.session:
            print "request.session['search_str'] = ", request.session['search_str']
        print "--------------------> search_str [e]"

        if search_str:
            if search_con == 'title':
                comm_list = TbBoard.objects.filter(use_yn='Y').filter(Q(subject__icontains=search_str)).order_by('-regist_date')
            else:
                comm_list = TbBoard.objects.filter(use_yn='Y').filter(Q(subject__icontains=search_str) | Q(content__icontains=search_str)).order_by('-regist_date')
        else:
            comm_list = TbBoard.objects.filter(use_yn='Y').order_by( '-regist_date')

        print "comm_list",comm_list

        p = Paginator(comm_list, page_size)
        total_cnt = p.count
        all_pages = p.num_pages
        curr_data = p.page(curr_page)

        with connections['default'].cursor() as cur:
            board_list = list()
            for board_data in curr_data.object_list:
                board_dict = dict()
                board_dict['board_id'] = board_data.board_id
                board_dict['subject'] = board_data.subject
                board_dict['content'] = board_data.content
                board_dict['gubun'] = board_data.gubun
                board_dict['use_yn'] = board_data.use_yn
                board_dict['delete_yn'] = board_data.delete_yn
                board_dict['head_title'] = board_data.head_title
                board_dict['regist_id'] = board_data.regist_id
                board_dict['regist_date'] = board_data.regist_date
                board_dict['modify_date'] = board_data.modify_date

                query = '''
                    SELECT count(seq)
                      FROM tb_board_store
                     WHERE board_id = {board_id} AND del_yn = 'N';
                '''.format(board_id=board_data.board_id)
                cur.execute(query)
                cnt = cur.fetchone()[0]

                if cnt != 0:
                    board_dict['attach_file'] = 'Y'
                else:
                    board_dict['attach_file'] = 'N'

                board_list.append(board_dict)

            context = {
                'total_cnt': total_cnt,
                'all_pages': all_pages,
                'curr_data': board_list,
            }

        return JsonResponse(context)

    else:
        if section == 'N':
            page_title = '공지사항'
        else:
            return None

        context = {
            'page_title': page_title,
            'curr_page': curr_page,
        }

        return render_to_response('community/comm_list.html', context)

@ensure_csrf_cookie
def comm_view(request, section='N', curr_page=None, board_id=None):

    #board_id = '1'

    logging.info("*********************************")
    logging.info('board_id -> ', board_id)
    logging.info("*********************************")
    board_id = int(board_id)

    #print "board_id -> ", board_id
    if section == 'N':
        page_title = '공지사항'
    else:
        return None

    context = {
        'page_title': page_title
    }

    # 게시판 삭제 기능 유효성 체크 [s]
    with connections['default'].cursor() as cur:
        query = '''
            select count(board_id)
            FROM tb_board
            where board_id = '{board_id}'
            and use_yn = 'D'
        '''.format(board_id=board_id)
        cur.execute(query)
        rows = cur.fetchall()

    #print "value -> ", rows[0][0]

    if rows[0][0] == 1:
        return render_to_response('community/comm_null.html', context)
    # 게시판 삭제 기능 유효성 체크 [e]

    if board_id is None:
        return redirect('/')


    board = TbBoard.objects.get(board_id=board_id)

    if board:
        board.files = TbBoardAttach.objects.filter(del_yn='N',board_id=board_id)

    board.regist_date = board.regist_date.strftime('%Y/%m/%d')
    #get modify_date with form YYYY-MM-DD
    board.modify_date = board.modify_date.strftime('%Y/%m/%d')

    if section == 'N':
        page_title = '공지사항'
    else:
        return None

    # 관리자에서 업로드한 경로와 실서버에서 가져오는 경로를 replace 시켜주어야함
    board.content = board.content.replace('/manage/home/static/upload/', '/static/file_upload/')

    # local test
    board.content = board.content.replace('/home/project/management/home/static/upload/', '/static/file_upload/')
    context = {
        'page_title': page_title,
        'board': board,
        # 'comm_list_url': reverse('file_check', kwargs={'section': section, 'curr_page': curr_page})
        'comm_list_url': reverse('comm_list', kwargs={'section': section,'curr_page': curr_page})
    }

    return render_to_response('community/comm_view.html', context)

@ensure_csrf_cookie
def comm_file(request, file_id=None):
    try:
        file = TbBoardAttach.objects.filter(del_yn='N').get(pk=file_id)
    except Exception as e:
        print 'comm_file error --- s'
        print e
        print connections['default'].queries
        print 'comm_file error --- e'
        return HttpResponse("<script>alert('파일이 존재하지 않습니다.'); window.history.back();</script>")

    filepath = file.file_path.replace('/manage/home/static/upload/', '/edx/var/edxapp/staticfiles/file_upload/') if file.file_path else '/edx/var/edxapp/staticfiles/file_upload/'
    filename = file.file_origin_name

    if not file or not os.path.exists(filepath + filename):
        print 'filepath + file.file_origin_name :', filepath + filename
        return HttpResponse("<script>alert('파일이 존재하지 않습니다 .'); window.history.back();</script>")

    response = HttpResponse(open(filepath + filename, 'rb'), content_type='application/force-download')

    response['Content-Disposition'] = 'attachment; filename=%s' % str(filename)
    return response


class TbBoard(models.Model):
    board_id = models.AutoField(primary_key=True)
    subject = models.TextField(11)
    content = models.TextField(blank=True, null=True)
    gubun = models.CharField(max_length=10, blank=True, null=True)
    use_yn = models.CharField(max_length=1)
    delete_yn = models.CharField(max_length=1)
    head_title = models.CharField(max_length=50, blank=True, null=True)
    regist_id = models.IntegerField()
    regist_date = models.DateTimeField()
    modify_date = models.DateTimeField()
    # section
    # N : notice, F: faq, K: k-mooc news, R: reference

    class Meta:
        managed = False
        db_table = 'tb_board'
        app_label='tb_board'


class TbBoardAttach(models.Model):
    seq = models.AutoField(primary_key=True)
    board_id = models.IntegerField(11)
    file_path = models.CharField(max_length=255)
    file_enc_name = models.CharField(max_length=255)
    file_origin_name = models.CharField(max_length=255, blank=True, null=True)
    file_ext = models.CharField(max_length=50, blank=True, null=True)
    file_size = models.CharField(max_length=50, blank=True, null=True)
    gubun = models.CharField(max_length=20, blank=True, null=True)
    del_yn = models.CharField(max_length=1)
    regist_id = models.IntegerField(blank=True, null=True)
    regist_date = models.DateTimeField(blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'tb_board_store'
        app_label = 'tb_board_store'
