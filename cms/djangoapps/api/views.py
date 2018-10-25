from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect
import MySQLdb as mdb
from bson.objectid import ObjectId
from pymongo import MongoClient

def video(request):

    database_ip = 'localhost'
    client = MongoClient(database_ip, 27017)
    #client = MongoClient('mongodb://edx.devstack.mongo:27017/')
    client.edxapp.authenticate("edxapp", "iU2aaH98IpI1HNCHn5k0uw43ZmpX8fMFN8S")

    db = client.edxapp
    org = request.GET.get('org')
    course_id = request.GET.get('course_id')
    run = request.GET.get('run')

    cursor_active_versions = db.modulestore.active_versions.find_one({'org': org, 'course': course_id, 'run': run})
    pb = cursor_active_versions.get('versions').get('published-branch')
    structure = db.modulestore.structures.find_one({'_id': ObjectId(pb)})
    blocks = structure.get('blocks')
    for block in blocks:
        block_type = block.get('block_id')
        if block_type == 'video':
            de = block.get('definition')
            definitions = db.modulestore.definitions.find_one({'_id': ObjectId(de)})

            print definitions.get('fields').get('data')
            print definitions.get('fields').get('data')
            print definitions.get('fields').get('data')
            print definitions.get('fields').get('data')
            video = definitions.get('fields').get('data')
            tmp = video[video.find('src') + 5:]
            video_link = tmp[:tmp.find('"')]

    return JsonResponse({'result': video_link})
