import psycopg
from datetime import datetime
from psycopg.rows import dict_row
import sys, os, json
from http.server import BaseHTTPRequestHandler, HTTPServer
from os import curdir, sep
import flask
from flask import render_template, Flask, request, redirect

app = Flask(__name__, static_folder="static")


def get_vulnerabilities():
    vulns=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT container_id,namespace, container, image, image_id, artifact_name, artifact_version, vuln_id, vuln_severity,
            vuln_datasource, vuln_fix_state, vuln_fix_versions
            FROM container_vulnerabilities;
            """)
        for row in cur:
            vulns.append(row)
    return vulns

def get_vulnerability_json(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT namespace, container, image, vulnscan, vulnscan_gen_date
            FROM containers
            WHERE id=%s ;
            """,(container_id,))
        return cur.fetchone()

def get_container_vulnerabilities(container_id):
    vulns=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT artifact_name, artifact_version, vuln_id, vuln_severity,
            vuln_datasource, vuln_fix_state, vuln_fix_versions
            FROM container_vulnerabilities
            WHERE container_id=%s ;
            """,(container_id,))
        for row in cur:
            vulns.append(row)
    return vulns

def get_sboms():
    sboms=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT container_id,namespace, container, image, image_id, artifact_id, artifact_name, artifact_version,
            artifact_type, artifact_language, artifact_purl
            FROM container_sbom;
            """)
        for row in cur:
            sboms.append(row)
    return sboms

def get_sbom_json(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT namespace, container, image, sbom, sbom_gen_date
            FROM containers
            WHERE id=%s ;
            """,(container_id,))
        return cur.fetchone()

def get_container_sboms(container_id):
    sboms=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT artifact_id, artifact_name, artifact_version, artifact_type,
            artifact_language, artifact_purl
            FROM container_sbom
            WHERE container_id=%s ;
            """,(container_id,))
        for row in cur:
            sboms.append(row)
    return sboms

def get_containers():
    containers=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, namespace, container, image, image_id, pod, k8s_running, last_pod_scan_date,
            sbom_generated, sbom_gen_date, vulnscan_generated, vulnscan_gen_date
            FROM containers;
            """)
        for row in cur:
            containers.append(row)
    return containers

def get_container(container_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id, namespace, container, image, image_id, pod, k8s_running, last_pod_scan_date,
            sbom_generated, sbom_gen_date, sbom, vulnscan_generated, vulnscan_gen_date, vulnscan
            FROM containers
            WHERE id = %s;
            """,(container_id,))
        for row in cur:
            return row

def get_ignorelist():
    ignorelist=[]
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            SELECT id as ignore_id, vuln_id, artifact_name, artifact_version, namespace, container, image, image_id
            FROM vuln_ignorelist;
            """)
        for row in cur:
            ignorelist.append(row)
    return ignorelist

def check_add_ignorelist(vuln_id,artifact_name,artifact_version,namespace,container,image,image_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            INSERT INTO vuln_ignorelist (vuln_id, artifact_name, artifact_version, namespace,
            container, image, image_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s);
            """,(vuln_id,artifact_name,artifact_version,namespace,container,image,image_id))
        success=bool(cur.rowcount)
        if success:
            rebuild_vulnerabilities()
        return bool(cur.rowcount)

def check_del_ignorelist(ignore_id):
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("""
            DELETE FROM vuln_ignorelist
            WHERE (id=%s);
            """,(ignore_id,))
        return bool(cur.rowcount)

def rebuild_vulnerabilities():
    with psycopg.connect(pdsn) as conn:
        cur = conn.cursor(row_factory=dict_row)
        cur.execute("REFRESH MATERIALIZED VIEW container_vulnerabilities;")
        return bool(cur.rowcount)

@app.route('/api/vulnerabilities',methods=['GET'])
def api_vulnerabilities():
    data={"data": get_vulnerabilities()}
    return data

@app.route('/api/container_vulnerabilities', methods=['GET'])
def api_container_vulnerabilities():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container_vulnerabilities(int(container_id_str))
    else:
        data={}
    rdata={"data": data}
    return rdata

@app.route('/api/sboms', methods=['GET'])
def api_sboms():
    data={"data": get_sboms()}
    return data

@app.route('/api/container_sboms', methods=['GET'])
def api_container_sboms():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container_sboms(int(container_id_str))
    else:
        data={}
    rdata={"data": data}
    return rdata

@app.route('/api/containers', methods=['GET'])
def api_containers():
    data={"data": get_containers()}
    return data

@app.route('/api/container', methods=['GET'])
def api_container():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_container(int(container_id_str))
    else:
        data={}
    return data

@app.route('/api/ignorelist', methods=['GET'])
def api_ignorelist():
    data={"data": get_ignorelist()}
    return data

@app.route('/api/addignorelist', methods=['POST'])
def api_addignorelist():
    fm=request.form
    added=check_add_ignorelist(fm['vuln_id'],fm['artifact_name'],fm['artifact_version'],fm['namespace'] \
        ,fm['container'],fm['image'],fm['image_id'])
    if added:
        formmessage="Successfully added, refreshing now..."
    else:
        formmessage="Error adding, likely duplicate, check ignorelist tab for details"
    return render_template('responseform.html',formmessage=formmessage)

@app.route('/api/delignorelist', methods=['POST'])
def api_delignorelist():
    dellist=request.get_json()
    success=True
    deletedAny = False
    if len(dellist) > 0:
        for delitem in dellist:
            delitemsuccess=check_del_ignorelist(delitem)
            if delitemsuccess:
                deletedAny=True
            else:
                success = False
    if deletedAny:
        rebuild_vulnerabilities()
    if success:
        formmessage="Successfully deleted Ignore List, refreshing now..."
    else:
        formmessage="Error deleting record. Retry"
    return render_template('responseform.html',formmessage=formmessage)

@app.route('/subform/addignorelist', methods=['GET'])
def app_subform_ignorelist():
    return render_template('add_ignorelist.html')


@app.route('/ignorelist/', methods = ['GET'])
def app_ignorelist():
    return render_template('ignorelist.html',APP_URL=APP_URL)

@app.route('/vulnerabilities/', methods=['GET'])
def app_vulnerabiliites():
    return render_template('vulnerabilities.html',APP_URL=APP_URL)

@app.route('/vulnerability/', methods=['GET'])
def app_vulnerability():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_vulnerability_json(int(container_id_str))
    else:
        data={}
    return render_template('vulnerability.html', data=data)

@app.route('/containers/', methods=['GET'])
def app_containers():
    return render_template('containers.html', APP_URL=APP_URL)

@app.route('/container/', methods=['GET'])
def app_container():
    container_id=request.args.get('id',None)
    return render_template('container.html',APP_URL=APP_URL, container_id=container_id)

@app.route('/sboms/', methods=['GET'])
def app_sboms():
    return render_template('sboms.html',APP_URL=APP_URL)

@app.route('/sbom/', methods=['GET'])
def app_sbom():
    container_id_str=request.args.get('id',None)
    if container_id_str.isnumeric():
        data=get_sbom_json(int(container_id_str))
    else:
        data={}
    return render_template('sbom.html', data=data)


@app.route('/', methods=['GET'])
def app_home():
    return redirect('/containers', code=302)

# main

db_host=os.environ.get('DB_HOST')
db_name=os.environ.get('DB_NAME')
db_user=os.environ.get('DB_USER')
db_password=os.environ.get('DB_PASSWORD')

APP_URL=os.environ.get('APP_URL')


pdsn="host=" + db_host + ' dbname=' + db_name + " user=" + db_user + " password=" + db_password

if (__name__ == '__main__'):
    app.run(host='0.0.0.0', port='80',debug=True)

sys.exit(0)
# TODO : archive old records???
