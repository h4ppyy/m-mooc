# -*- coding: utf-8 -*- 

import logging
import os
import cx_Oracle
import MySQLdb as mdb

buf = {}
cnt_all = 0
cnt_true = 0
cnt_false = 0

def user_ora_human_update(rnn_go):
    #http://localhost:18000/userhumanupdate?rnn_go=1
    #import os

    mycon = None
    mycur = None
    con = None
    cur = None
    try:
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

        print 1
        #dsn = ora.makedsn(MOBIS_DB_IP, MOBIS_DB_PORT, MOBIS_DB_SID)
        #db = ora.connect(MOBIS_DB_USR, MOBIS_DB_PWD, dsn)
        con = cx_Oracle.connect("SWAUSER", "mbora#SW252", "10.230.22.252:1521/mobispdm")
        os.putenv('NLS_LANG', 'UTF8')
        print 2
        # db = ora.connect("scott/tiger@127.0.0.1/XE")
        cur = con.cursor()
        print 3

        sql = """select userenv('LANGUAGE') from dual"""
        logging.info('query: %s', sql)
        buf['msg1'] = 'query:{0}'.format(sql)
        cur.execute(sql)

        print 4
        for row in cur.fetchall():
            print row

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
        print query

        logging.info('query: %s', query)
        buf['msg1'] = 'query:{0}'.format(query)
        cur.execute(query)

        print 4
        for row in cur.fetchall():
            results.append(row)

        print 5
        mycon = None
        #mycon = mdb.connect(settings.DATABASES.get('default').get('HOST'),
        #                  settings.DATABASES.get('default').get('USER'),
        #                  settings.DATABASES.get('default').get('PASSWORD'),
        #                  settings.DATABASES.get('default').get('NAME'),
        #                  charset='utf8')

        print 6
        mycon = mdb.connect(host='localhost', user='root', passwd='', db='edxapp', charset='utf8')

        print 7

        # Connection 으로부터 Cursor 생성
        logging.info("views.py def index user_human_connect", "test")
        buf['msg2'] = 'views.py def index user_human_connect'
        mycur = mycon.cursor()

        print 8
        #mycon, mycur = user_human_connect()

        # MySQL Insert processing
        try:
            cnt = 0
            for row in results:
                cnt = cnt + 1
                user_id = row[0]    # USER_ID
                user_nm = row[1]    # USER_KN
                email = user_id+'@mobis.co.kr'    # email
                #logging.info("****user_id:%s, user_nm: %s, email: %s", user_id, user_nm, email)
                #buf['msg3'] = "****user_id:{0}, user_nm: {1}, email: {2}".format(user_id, user_nm, email)
                print "****user_id:{0}, user_nm: {1}, email: {2}".format(user_id, user_nm, email)
                user_human_update(mycon, mycur, user_nm, user_id, email)
                #if cnt > 50: 
                #    break
            print 'cnt_all:{0}, cnt_true:{1} cnt_false:{2}', cnt_all,  cnt_true, cnt_false
        except:
            print 'error {0}'.format(e)

        print 9 
        json_return = {}
        json_return['status'] = 'OK'

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
        if con is not None:
            con.close()
        return 'OK'

def user_human_update(con, cur, user_nm, username, email):
    # user_human_update(mycon, mycur, user_nm, user_id, email)
    try:
        # SQL문 실행
        #user_id = 0
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)

        print sql

        # 데이타 Fetch
        rows = cur.fetchall()
        exists_flag = False
        for row in rows:
            id = row[0]
            exists_flag = True
            break

        global cnt_all
        global cnt_true
        global cnt_false

        cnt_all = cnt_all + 1
        if exists_flag:
            cnt_true = cnt_true + 1
            print 'all data count:{0}, no data count:{1}', cnt_all, cnt_true
            sql1 = """
                  update auth_user set username = \'{username}\', last_name = \'{last_name}\' where email = \'{email}\'
                  """.format(username=username, last_name=user_nm, email=email)
            print sql1
            cur.execute(sql1)
            # print cur.rowcount, "record(s) affected"
            logging.info("views.py def index user_human_update : %d record(s) affected", cur.rowcount)
            buf['msg4'] = "views.py def index user_human_update : {0} record(s) affected".format(cur.rowcount)
            print "views.py def index user_human_update : {0} record(s) affected".format(cur.rowcount)

            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            con.commit()
            #print cur.rowcount, "record(s) affected"
            logging.info("views.py def index user_human_update : %d record(s) affected", cur.rowcount)
            buf['msg5'] = "views.py def index user_human_update : {0} record(s) affected".format(cur.rowcount)
            print "views.py def index user_human_update : {0} record(s) affected".format(cur.rowcount)
        else:
            if 1==1:
                cnt_false = cnt_false + 1
                print 'all data count:{0}, no data count:{1}', cnt_all, cnt_false
                #print "0 record(s) affected"
                # if u not fuound, insert in mysql
                import uuid
                # 32 bytes password
                _uuid = uuid.uuid4().__str__()
                _uuid = _uuid.replace('-', '')

                #cmd = 'bash /edx/app/edxapp/edx-platform/add_user.sh {email} {password} {username}'.format(
                cmd = 'bash /edx/app/edxapp/edx-platform/add_user_bat.sh {email} {password} {username}'.format(
                    email=email,
                    password=_uuid,
                    username=username)
                logging.info('%s Shell script : %s', 'views.py def index user_human_update', cmd)
                print '{0} Shell script : {1}'.format('views.py def index user_human_update', cmd)
                result = os.system(cmd)
                # auth_user update
                user_human_info_update(con, cur, user_nm, email)

    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)
        print 'views.py def index user_human_update MySQL: {0}'.format(e)

def user_human_info_update(con, cur, user_nm, email):
    try:
        # SQL문 실행
        user_id = 0
        sql = """
              select id from auth_user where email = \'{email}\'
              """.format(email=email)
        cur.execute(sql)

        buf['msg6'] = "****query 1 : {0}".format(sql)
        print "****query 1 : {0}".format(sql)
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
            #buf['msg7'] = "****query 2 : {0}".format(sql1)
            print "****query 2-1 : {0}".format(sql1)

            sql2 = """
                  update auth_userprofile set name = \'{user_nm}\' where user_id = {id}
                  """.format(user_nm=user_nm, id=id)
            cur.execute(sql2)
            #buf['msg8'] = "****query 2 : {0}".format(sql2)
            print "****query 2-2 : {0}".format(sql2)
            con.commit()
            logging.info("views.py def index user_human_info_update : %d record(s) affected", cur.rowcount)
            #buf['msg9'] = "views.py def index user_human_info_update : {0} record(s) affected".format(cur.rowcount)
            print "views.py def index user_human_info_update : {0} record(s) affected".format(cur.rowcount)
        else:
            logging.info("views.py def index user_human_info_update : %s record(s) affected", '0')
            #buf['msg10'] = "views.py def index user_human_info_update : 0 record(s) affected"
            print "views.py def index user_human_info_update : 0 record(s) affected"
    except mdb.Error, e:
        logging.info('views.py def index user_human_update MySQL: %s', e)
        #buf['msg11'] = 'views.py def index user_human_update MySQL: {0}'.format(e)
        print 'views.py def index user_human_update MySQL: {0}'.format(e)

gDebug = False
gDebug = True
if gDebug:
    if __name__ == "__main__":
        r = user_ora_human_update(1)
        print r
        r = user_ora_human_update(2)
        print r

